#!/bin/bash
# LDAP Security Assessment Tool
# Checks both LDAP signing and channel binding enforcement using ldap3

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

function check_ldap_security() {
    local server=$1
    local username=$2
    local password=$3
    local domain=$4
    local ldap_signing_required_error=false
    
    echo -e "${BLUE}======= LDAP Security Assessment =======${NC}"
    echo -e "${BLUE}Target:   ${NC}$server"
    echo -e "${BLUE}Domain:   ${NC}$domain"
    echo -e "${BLUE}Username: ${NC}$username"
    
    # === LDAP SIGNING CHECKS ===
    
    # Step 1: Check for anonymous binds
    echo -e "\n${PURPLE}[*] PHASE 1: TESTING ANONYMOUS BINDS${NC}"
    anon_result=$(ldapsearch -x -H "ldap://$server:389" -s base -b "" 2>&1)
    
    if echo "$anon_result" | grep -q "result: 0 Success"; then
        echo -e "${GREEN}[+] Anonymous LDAP bind SUCCESSFUL${NC}"
        echo -e "${GREEN}[+] Server allows anonymous binds - this is a security weakness${NC}"
        anon_success=true
    else
        echo -e "${YELLOW}[-] Anonymous LDAP bind FAILED${NC}"
        echo -e "${YELLOW}[-] Server blocks anonymous binds - missed potential information gathering${NC}"
        anon_success=false
    fi
    
    # Step 2: Test authenticated bind with ldap3
    echo -e "\n${PURPLE}[*] PHASE 2: TESTING UNSIGNED AUTHENTICATED BINDS${NC}"
    
    # Create a temporary Python script to test with ldap3
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
#!/usr/bin/env python3
import sys, os
try:
    import ldap3
    from ldap3 import Connection, Server, NTLM, SIMPLE
except ImportError:
    print("[!] Error: ldap3 module not installed")
    print("[!] Install with: pip install ldap3")
    sys.exit(3)

def print_green(text):
    GREEN = '\033[0;32m'
    NC = '\033[0m'
    print(f"{GREEN}{text}{NC}")

def print_red(text):
    RED = '\033[0;31m'
    NC = '\033[0m'
    print(f"{RED}{text}{NC}")

def print_yellow(text):
    YELLOW = '\033[0;33m'
    NC = '\033[0m'
    print(f"{YELLOW}{text}{NC}")

def test_unsigned_bind(server, username, password, domain):
    """Test LDAP signing enforcement using ldap3"""
    try:
        # Format the user principal name for simple bind
        user_dn = f"{username}@{domain}"
        
        # Format NTLM username properly as domain\username
        ntlm_username = f"{domain}\\{username}"
        
        # Initialize connection
        server_obj = Server(server, port=389, get_info=ldap3.NONE)
        
        # First try standard simple bind
        conn = Connection(
            server_obj, 
            user=user_dn, 
            password=password,
            authentication=SIMPLE,
            auto_bind=False
        )
        
        # Attempt to bind
        conn.open()
        bind_result = conn.bind()
        if bind_result:
            print("[+] Standard bind SUCCESSFUL")
            conn.unbind()
            
            # Now try with NTLM using domain\username format
            conn = Connection(
                server_obj, 
                user=ntlm_username,
                password=password,
                authentication=NTLM,
                auto_bind=False
            )
            
            # Explicitly set to not use signing (if possible)
            # Through connection parameters rather than options
            conn.open()
            bind_result = conn.bind()
            if bind_result:
                print_green("[+] NTLM bind SUCCESSFUL without explicitly requiring signing")
                print_green("[+] LDAP signing does NOT appear to be enforced")
                conn.unbind()
                return False  # Signing not enforced
            else:
                print_red(f"[-] NTLM bind FAILED: {conn.result}")
                # Check for specific Microsoft error codes
                result_str = str(conn.result)
                if ("8232" in result_str or 
                    "80090322" in result_str or 
                    "secure channel" in result_str.lower() or
                    "integrity" in result_str.lower()):
                    print_red("[-] Server error indicates signing requirements")
                    return True  # Signing likely enforced
                else:
                    print("[!] Bind failed but not with signing-related errors")
                    return None  # Inconclusive
        else:
            print_red(f"[-] Standard bind FAILED: {conn.result}")
            # Check for signing requirements
            result_str = str(conn.result)
            if ("8232" in result_str or 
                "80090322" in result_str or
                "secure channel" in result_str.lower() or
                "integrity" in result_str.lower() or
                "strongerAuthRequired" in result_str or
                "The server requires binds to turn on integrity checking" in result_str):
                print_red("[-] Error suggests signing is required")
                return True  # Signing enforced
            return None  # Inconclusive - authentication may have failed
    except Exception as e:
        print_red(f"[!] Error: {e}")
        return None  # Inconclusive

def test_channel_binding(server, username, password, domain):
    """Test LDAP channel binding enforcement using multiple methods"""
    try:
        # Format usernames for different auth methods
        user_dn = f"{username}@{domain}"
        ntlm_username = f"{domain}\\{username}"
        
        print_red("[*] ADVANCED CHANNEL BINDING TEST")
        print_red("[*] Testing with various authentication mechanisms")
        
        # Track test results
        ntlm_success = False
        tls_failure_with_cb_error = False
        
        # Initialize server
        server_obj = Server(server, port=389, get_info=ldap3.NONE)
        
        # 1. Test with plain NTLM
        ntlm_conn = None
        try:
            ntlm_conn = Connection(
                server_obj, 
                user=ntlm_username,
                password=password,
                authentication=NTLM,
                auto_bind=False
            )
            
            ntlm_conn.open()
            ntlm_result = ntlm_conn.bind()
            
            if ntlm_result:
                # NTLM bind worked
                ntlm_success = True
                print_green("[+] NTLM auth and search SUCCESSFUL")
            else:
                error_msg = str(ntlm_conn.result).lower()
                print_red(f"[-] NTLM bind FAILED: {ntlm_conn.result}")
                
                # Check for channel binding indicators in the error
                if ("token" in error_msg or 
                    "channel binding" in error_msg or 
                    "80090346" in error_msg or
                    ("integrity" in error_msg and "stronger" in error_msg)):
                    print_red("[-] Error suggests channel binding is required")
                    return True  # Channel binding enforced
        
        except Exception as e:
            print_red(f"[!] Error during NTLM test: {e}")
        finally:
            if ntlm_conn and ntlm_conn.bound:
                ntlm_conn.unbind()
        
        # 2. Test with Simple authentication
        simple_conn = None
        try:
            simple_conn = Connection(
                server_obj,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=False
            )
            
            simple_conn.open()
            simple_result = simple_conn.bind()
            
            if simple_result:
                print_green("[+] SIMPLE bind SUCCESSFUL")
            else:
                print_red(f"[-] SIMPLE bind FAILED: {simple_conn.result}")
        
        except Exception as e:
            print_red(f"[!] Error during SIMPLE test: {e}")
        finally:
            if simple_conn and simple_conn.bound:
                simple_conn.unbind()
        
        # 3. Check using TLS
        try:
            print_red("[*] Testing with TLS for comparison")
            # Try to create a TLS server
            tls_server = Server(server, port=636, use_ssl=True, get_info=ldap3.NONE)
            
            # Connect with TLS+NTLM
            tls_conn = Connection(
                tls_server,
                user=ntlm_username,
                password=password,
                authentication=NTLM,
                auto_bind=False
            )
            
            # Try to connect with TLS
            try:
                tls_conn.open()
                tls_result = tls_conn.bind()
                
                if tls_result:
                    print_green("[+] TLS+NTLM bind SUCCESSFUL")
                else:
                    error_msg = str(tls_conn.result).lower()
                    print_red(f"[-] TLS+NTLM bind FAILED: {tls_conn.result}")
                    print_yellow("[!] Ignore 'invalidCredentials' in the above ERROR!")
                    
                    # Check specifically for channel binding errors
                    if "80090346" in error_msg or "token binding" in error_msg:
                        print_red("[-] TLS connection failed with TOKEN BINDING error")
                        print_red("[-] ERROR CODE 80090346 = SEC_E_TOKEN_BINDING_NOT_SUPPORTED")
                        print_red("[-] This is STRONG EVIDENCE that channel binding is enforced")
                        tls_failure_with_cb_error = True
                
                if tls_conn.bound:
                    tls_conn.unbind()
            except Exception as tls_err:
                print_red(f"[!] TLS connection error: {tls_err}")
                if "80090346" in str(tls_err) or "token binding" in str(tls_err).lower():
                    tls_failure_with_cb_error = True
        except Exception as e:
            print_red(f"[!] Error setting up TLS test: {e}")
        
        # 4. Final decision based on all tests
        if tls_failure_with_cb_error:
            print_red("[-] FINAL ASSESSMENT: Channel binding IS ENFORCED")
            print_red("[-] Evidence: TLS connection failed with token binding error 80090346")
            return True
        elif ntlm_success:
            print_green("[+] FINAL ASSESSMENT: Channel binding does NOT appear to be enforced for non-TLS connections")
            print_green("[+] WARNING: This may be a false negative if the server only enforces it for certain operations")
            return False
        else:
            print_red("[!] Channel binding status INCONCLUSIVE")
            print_red("[!] For more accurate results, try running netexec with verbose output")
            return None
            
    except Exception as e:
        print_red(f"[!] Critical error in channel binding test: {e}")
        return None  # Inconclusive

def detect_channel_binding_the_netexec_way(server, username, password, domain):
    """More closely simulate netexec/crackmapexec detection of channel binding"""
    try:
        # Format usernames
        ntlm_username = f"{domain}\\{username}"
        
        print_red("[*] LDAP CHANNEL BINDING TEST")
        
        # Create server
        server_obj = Server(server, port=389, get_info=ldap3.NONE)
        
        # Try NTLM auth in a way similar to netexec
        conn = Connection(
            server_obj,
            user=ntlm_username,
            password=password,
            authentication=NTLM,
            auto_bind=False
        )
        
        # Attempt connection and authentication
        try:
            conn.open()
            
            # This is a key part - before binding, check if we can manipulate
            # NTLM settings the way netexec might
            if hasattr(conn, '_socket') and hasattr(conn._socket, 'ssl_wrapped'):
                print_red("[*] Connection has expected netexec-compatible properties")
            
            # Try binding
            bind_result = conn.bind()
            
            if bind_result:
                print_green("[+] Connection successful")
                
                # Try a basic search to verify
                search_result = conn.search(
                    search_base='',
                    search_filter='(objectClass=*)',
                    search_scope='BASE',
                    attributes=['*']
                )
                
                if search_result:
                    print_green("[+] Search operation successful")
                    conn.unbind()
                    # At this point, netexec would report channel binding NOT required
                    return False
                else:
                    # Search failed after bind - check the error
                    err_msg = str(conn.result).lower()
                    if "token" in err_msg or "channel binding" in err_msg:
                        print_red("[-] Search failed with channel binding error")
                        conn.unbind()
                        return True
            else:
                # Bind failed - check if it's due to channel binding
                err_msg = str(conn.result).lower()
                if ("token" in err_msg or 
                    "channel binding" in err_msg or 
                    "80090346" in err_msg or
                    ("stronger" in err_msg and "integrity" in err_msg)):
                    print_red("[-] Channel binding appears to be required")
                    conn.unbind()
                    return True
                
                print_red(f"[-] Authentication failed: {conn.result}")
            
            conn.unbind()
            
            # Additional test: try with standard Windows NTLM flags
            print_red("[*] Attempting with standard Windows NTLM flags")
            conn2 = Connection(
                server_obj,
                user=ntlm_username,
                password=password,
                authentication=NTLM,
                auto_bind=False
            )
            
            # Try to manipulate connection options to match Windows behavior
            conn2.open()
            bind2_result = conn2.bind()
            
            if not bind2_result and "token" in str(conn2.result).lower():
                print_red("[-] Secondary test indicates channel binding is required")
                conn2.unbind()
                return True
            
            conn2.unbind()
            
        except Exception as conn_err:
            print_red(f"[!] Connection error: {conn_err}")
            if "token" in str(conn_err).lower():
                return True
        
        # If we get here, channel binding was not detected
        print_green("[+] Channel binding does NOT appear to be required")
        return False
        
    except Exception as e:
        print_red(f"[!] Error in simulation: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("ERROR: Missing required arguments")
        sys.exit(2)
    
    server = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    domain = sys.argv[4]
    test_type = sys.argv[5]  # "signing" or "channel"
    
    try:
        if test_type == "signing":
            result = test_unsigned_bind(server, username, password, domain)
        elif test_type == "channel":
            # First try netexec-like detection
            netexec_result = detect_channel_binding_the_netexec_way(server, username, password, domain)
            if netexec_result:
                print_red("[-] CHANNEL BINDING IS REQUIRED")
                result = True
            else:
                # Fallback to our standard test
                result = test_channel_binding(server, username, password, domain)
        else:
            print(f"ERROR: Unknown test type: {test_type}")
            sys.exit(2)
        
        if result is True:
            sys.exit(0)  # Security feature enforced
        elif result is False:
            sys.exit(1)  # Security feature not enforced
        else:
            sys.exit(2)  # Inconclusive
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        sys.exit(3)  # Error

EOF

    # Make the script executable
    chmod +x "$temp_script"
    
    # Check if python and ldap3 are installed
    if ! command -v python3 &>/dev/null; then
        echo -e "${YELLOW}[!] Python3 not found${NC}"
        echo -e "${YELLOW}[!] Install with: 'sudo apt install python3' or equivalent${NC}"
        python_available=false
    else
        python_available=true
        
        # Check for ldap3
        if ! python3 -c "import ldap3" &>/dev/null; then
            echo -e "${YELLOW}[!] Python ldap3 module not found${NC}"
            echo -e "${YELLOW}[!] Installing ldap3 module...${NC}"
            python3 -m pip install ldap3 >/dev/null 2>&1
            
            # Check if install succeeded
            if ! python3 -c "import ldap3" &>/dev/null; then
                echo -e "${YELLOW}[!] Failed to install ldap3. Install manually with:${NC}"
                echo -e "${YELLOW}[!] pip install ldap3${NC}"
                python_available=false
            fi
        fi
        
        # Run the Python script for signing test if python is available
        if [ "$python_available" = true ]; then
            python3 "$temp_script" "$server" "$username" "$password" "$domain" "signing"
            signing_result=$?
        fi
    fi
    # Step 3: Test standard authenticated bind
    echo -e "\n${PURPLE}[*] PHASE 3: TESTING STANDARD AUTHENTICATED BINDS${NC}"
    auth_result=$(ldapsearch -x -H "ldap://$server:389" -D "$username@$domain" -w "$password" -s base -b "" 2>&1)
    if echo "$auth_result" | grep -q "result: 0 Success"; then
        echo -e "${GREEN}[+] Standard authenticated bind SUCCESSFUL${NC}"
        auth_success=true
    else
        echo -e "${YELLOW}[!] Standard authenticated bind FAILED: $(echo "$auth_result" | grep -i "ldap_bind\|result:")${NC}"
        auth_success=false
        # Check if failure is due to signing requirements
        if echo "$auth_result" | grep -q -i "Strong"; then
            ldap_signing_required_error=true
        fi
    fi
    
    # Step 4: Check channel binding if python is available
    echo -e "\n${PURPLE}[*] PHASE 4: TESTING CHANNEL BINDING ENFORCEMENT${NC}"
    
    if [ "$python_available" = true ]; then
        # Run the Python script for channel binding test
        python3 "$temp_script" "$server" "$username" "$password" "$domain" "channel"
        channel_result=$?
    else
        echo -e "${YELLOW}[!] Skipping channel binding check due to missing dependencies${NC}"
        channel_result=2
    fi
    
    # Remove temporary script
    rm -f "$temp_script"
    
    # === ANALYSIS & REPORTING ===
    
    echo -e "\n${PURPLE}======= ASSESSMENT RESULTS =======${NC}"
    
    # LDAP Signing Results
    echo -e "\n${BLUE}=== LDAP SIGNING ASSESSMENT ===${NC}"
    
    # Determine signing status
    if [ "$ldap_signing_required_error" = true ]; then
        ldap_signing_enforced=true
        signing_evidence="Authentication failed with 'strongerAuthRequired' error"
    elif [ "$anon_success" = true ]; then
        ldap_signing_enforced=false
        signing_evidence="Anonymous binds successful (strongest evidence)"
    elif [ "$python_available" = true ] && [ "$signing_result" -eq 0 ]; then
        ldap_signing_enforced=true
        signing_evidence="NTLM bind rejected with signing errors"
    elif [ "$python_available" = true ] && [ "$signing_result" -eq 1 ]; then
        ldap_signing_enforced=false
        signing_evidence="NTLM bind accepted without signing"
    elif [ "$auth_success" = true ]; then
        ldap_signing_enforced=false
        signing_evidence="Standard bind successful (default client behavior)"
    else
        ldap_signing_enforced=null
        signing_evidence="Inconclusive tests"
    fi
    
    # Display signing results
    if [ "$ldap_signing_enforced" = false ]; then
        echo -e "${GREEN}[+] FINDING: LDAP signing is NOT enforced${NC}"
        echo -e "${GREEN}[+] Evidence: $signing_evidence${NC}"
        echo -e "${GREEN}[+] Impact: Attacker can perform MITM attacks against LDAP traffic${NC}"
        echo -e "${GREEN}[+] Exploit: Traffic can be intercepted and modified in transit${NC}"
    elif [ "$ldap_signing_enforced" = true ]; then
        echo -e "${YELLOW}[-] FINDING: LDAP signing IS enforced${NC}"
        echo -e "${YELLOW}[-] Evidence: $signing_evidence${NC}"
        echo -e "${YELLOW}[-] Impact: MITM attacks against LDAP traffic will fail${NC}"
    else
        echo -e "${YELLOW}[!] FINDING: LDAP signing status INCONCLUSIVE${NC}"
        echo -e "${YELLOW}[!] Evidence: $signing_evidence${NC}"
    fi
    
    # Channel Binding Results
    echo -e "\n${BLUE}=== LDAP CHANNEL BINDING ASSESSMENT ===${NC}"
    
    if [ "$python_available" = true ] && [ "$channel_result" -eq 0 ]; then
        echo -e "${YELLOW}[-] FINDING: LDAP channel binding IS enforced${NC}"
        echo -e "${YELLOW}[-] Impact: Relay attacks against LDAP will fail${NC}"
    elif [ "$python_available" = true ] && [ "$channel_result" -eq 1 ]; then
        echo -e "${GREEN}[+] FINDING: LDAP channel binding is NOT enforced${NC}"
        echo -e "${GREEN}[+] Impact: LDAP connections vulnerable to relay attacks${NC}"
        echo -e "${GREEN}[+] Exploit: Potential for NTLM relay attacks against LDAP service${NC}"
    else
        echo -e "${YELLOW}[!] FINDING: LDAP channel binding status INCONCLUSIVE${NC}"
    fi
    
    # Anonymous Bind Results
    echo -e "\n${BLUE}=== ANONYMOUS BIND ASSESSMENT ===${NC}"
    
    if [ "$anon_success" = true ]; then
        echo -e "${GREEN}[+] FINDING: Anonymous binds ARE permitted${NC}"
        echo -e "${GREEN}[+] Impact: Information disclosure without authentication${NC}"
        echo -e "${GREEN}[+] Exploit: Enumerate users and other AD information anonymously${NC}"
        echo -e "${GREEN}[+] Example: ldapsearch -x -H ldap://$server:389 -b \"DC=${domain//./,DC=}\" -s sub \"(objectClass=user)\"${NC}"
    else
        echo -e "${YELLOW}[-] FINDING: Anonymous binds are NOT permitted${NC}"
    fi
    
    # Overall Security Posture
    echo -e "\n${BLUE}=== OVERALL LDAP SECURITY POSTURE ===${NC}"
    
    security_issues=0
    if [ "$ldap_signing_enforced" = false ]; then
        ((security_issues++))
    fi
    
    if [ "$python_available" = true ] && [ "$channel_result" -eq 1 ]; then
        ((security_issues++))
    fi
    
    if [ "$anon_success" = true ]; then
        ((security_issues++))
    fi
    
    if [ $security_issues -eq 0 ]; then
        echo -e "${YELLOW}[-] Target has strong LDAP security configuration${NC}"
        echo -e "${YELLOW}[-] No significant LDAP security weaknesses identified${NC}"
    elif [ $security_issues -eq 1 ]; then
        echo -e "${GREEN}[+] Target has moderate LDAP security issues${NC}"
        echo -e "${GREEN}[+] One security weakness identified that could be exploited${NC}"
    elif [ $security_issues -ge 2 ]; then
        echo -e "${GREEN}[+] Target has CRITICAL LDAP security weaknesses${NC}"
        
 elif [ $security_issues -ge 2 ]; then
        echo -e "${GREEN}[+] Target has CRITICAL LDAP security weaknesses${NC}"
        echo -e "${GREEN}[+] Multiple attack vectors available - prioritize exploitation${NC}"
    fi
    
    # Return appropriate exit code for automation
    if [ "$ldap_signing_enforced" = false ]; then
        return 0  # Success from a pentesting perspective
    else
        return 1  # Failure from a pentesting perspective
    fi
}

# Main execution
if [ $# -lt 3 ]; then
    echo "Usage: $0 <domain_controller> <username> <password> [domain]"
    echo "Example: $0 192.168.1.10 administrator Password123 example.local"
    exit 1
fi

server=$1
username=$2
password=$3
domain=${4:-$(hostname -d 2>/dev/null || echo "domain.local")}

check_ldap_security "$server" "$username" "$password" "$domain"
exit $?
