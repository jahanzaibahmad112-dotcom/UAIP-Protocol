import json

def generate_compliance_report():
    """Layer 4: Automated Evidence Collection for SOC2/ISO27001"""
    try:
        with open("audit_trail.json", "r") as f:
            logs = f.readlines()
        
        print("--- UAIP COMPLIANCE REPORT (SOC2 / EU AI ACT) ---")
        for line in logs:
            log = json.loads(line)
            print(f"Evidence ID: {log['id']} | Agent: {log['agent']} | Status: {log['decision']} | Audit: VERIFIED")
        print("-------------------------------------------------")
    except FileNotFoundError:
        print("No audit logs found yet.")

if __name__ == "__main__":
    generate_compliance_report()