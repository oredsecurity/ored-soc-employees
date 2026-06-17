#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define LOG_NAME "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
#define RULE_NAME "ORED ARGOS BLOCKED IP"

static void log_line(const char *msg) {
    FILE *f = fopen(LOG_NAME, "a");
    if (!f) return;
    SYSTEMTIME st;
    GetSystemTime(&st);
    fprintf(f, "%04u/%02u/%02u %02u:%02u:%02u ored-win-firewall: %s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
}

static int is_ip_char(char c) {
    return isdigit((unsigned char)c) || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int valid_ip(const char *ip) {
    int dots = 0;
    size_t len = strlen(ip);
    if (len < 3 || len > 45) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!is_ip_char(ip[i])) return 0;
        if (ip[i] == '.') dots++;
    }
    return dots == 3 || strchr(ip, ':') != NULL;
}

static void extract_until_quote_or_comma(const char *start, char *out, size_t out_len) {
    size_t i = 0;
    while (start[i] && start[i] != '"' && start[i] != '\\' && start[i] != ',' && start[i] != ']' && i + 1 < out_len) {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
}

static int parse_payload(const char *payload, char *action, size_t action_len, char *ip, size_t ip_len) {
    const char *p;
    strncpy(action, "add", action_len - 1);
    action[action_len - 1] = '\0';
    ip[0] = '\0';

    if (strstr(payload, "ored-win-firewall-rollback") || strstr(payload, "ored-win-firewall-unblock") || strstr(payload, "ored-win-firewall-delete")) {
        strncpy(action, "delete", action_len - 1);
    }
    if (strstr(payload, "ored-win-firewall-v3") || strstr(payload, "ored-win-firewall-block") || strstr(payload, "ored-win-firewall-add")) {
        strncpy(action, "add", action_len - 1);
    }
    if (strstr(payload, "action=delete")) strncpy(action, "delete", action_len - 1);
    if (strstr(payload, "action=status")) strncpy(action, "status", action_len - 1);
    if (strstr(payload, "action=add")) strncpy(action, "add", action_len - 1);

    p = strstr(payload, "srcip=");
    if (p) extract_until_quote_or_comma(p + 6, ip, ip_len);
    if (ip[0] == '\0') {
        p = strstr(payload, "\"srcip\":\"");
        if (p) extract_until_quote_or_comma(p + 9, ip, ip_len);
    }
    if (ip[0] == '\0') {
        p = strstr(payload, "\"srcip\": \"");
        if (p) extract_until_quote_or_comma(p + 10, ip, ip_len);
    }
    return valid_ip(ip);
}

static int run_command(const char *cmdline) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 1;
    char mutable_cmd[4096];
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    strncpy(mutable_cmd, cmdline, sizeof(mutable_cmd) - 1);
    mutable_cmd[sizeof(mutable_cmd) - 1] = '\0';
    if (!CreateProcessA(NULL, mutable_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return (int)GetLastError();
    }
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

static int rule_exists(const char *ip) {
    char cmd[4096];
    snprintf(
        cmd,
        sizeof(cmd),
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
        "$ip='%s'; "
        "$rules = Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; "
        "$match = $rules | Where-Object { (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress -contains $ip }; "
        "if ($match) { exit 0 } else { exit 1 }\"",
        ip,
        RULE_NAME);
    return run_command(cmd) == 0;
}

static int delete_rule(const char *ip) {
    char cmd[4096];
    if (!rule_exists(ip)) return 0;
    snprintf(
        cmd,
        sizeof(cmd),
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
        "$ip='%s'; "
        "Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | "
        "Where-Object { (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress -contains $ip } | "
        "Remove-NetFirewallRule\"",
        ip,
        RULE_NAME);
    run_command(cmd);
    return rule_exists(ip) ? 1 : 0;
}

static int add_rule(const char *ip) {
    char cmd[4096];
    int rc;
    if (rule_exists(ip)) return 0;
    snprintf(
        cmd,
        sizeof(cmd),
        "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"%s\" "
        "dir=in action=block remoteip=%s/32 protocol=any profile=any",
        RULE_NAME,
        ip);
    rc = run_command(cmd);
    if (rc != 0) return rc;
    return rule_exists(ip) ? 0 : 1;
}

static int wazuh_continue(const char *action, const char *ip) {
    char response[8192];
    char key[128];
    snprintf(key, sizeof(key), "ored-win-firewall:%s:%s", action, ip);
    printf("{\"version\":1,\"origin\":{\"name\":\"ored-win-firewall\",\"module\":\"active-response\"},\"command\":\"check_keys\",\"parameters\":{\"keys\":[\"%s\"]}}\n", key);
    fflush(stdout);

    if (!fgets(response, sizeof(response), stdin)) {
        log_line("error no continue response from wazuh-execd");
        return 0;
    }
    if (strstr(response, "\"command\":\"continue\"") || strstr(response, "\"command\": \"continue\"")) {
        return 1;
    }
    log_line("active response aborted by wazuh-execd");
    return 0;
}

int main(void) {
    char payload[8192];
    char action[16];
    char ip[64];
    char logbuf[256];
    int rc;

    if (!fgets(payload, sizeof(payload), stdin)) {
        log_line("error no active-response JSON received");
        return 1;
    }
    if (!parse_payload(payload, action, sizeof(action), ip, sizeof(ip))) {
        log_line("error invalid or missing srcip");
        return 1;
    }

    snprintf(logbuf, sizeof(logbuf), "requested action=%s srcip=%s", action, ip);
    log_line(logbuf);

    if (!wazuh_continue(action, ip)) {
        return 0;
    }

    if (strcmp(action, "status") == 0) {
        rc = rule_exists(ip) ? 0 : 1;
        snprintf(logbuf, sizeof(logbuf), "status srcip=%s rc=%d", ip, rc);
        log_line(logbuf);
        return 0;
    }
    if (strcmp(action, "delete") == 0) {
        rc = delete_rule(ip);
        snprintf(logbuf, sizeof(logbuf), "delete srcip=%s rc=%d", ip, rc);
        log_line(logbuf);
        return rc == 0 ? 0 : 1;
    }

    rc = add_rule(ip);
    snprintf(logbuf, sizeof(logbuf), "add srcip=%s rc=%d", ip, rc);
    log_line(logbuf);
    return rc == 0 ? 0 : 1;
}
