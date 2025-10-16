import streamlit as st
import socket
import ipaddress
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import time

# Page configuration
st.set_page_config(page_title="AI-Powered IP Scanner", page_icon="🔍", layout="wide")

# Title and description
st.title("🔍 AI-Powered IP Scanner")
st.markdown("Ask in natural language to scan IP ranges and find open hosts!")

# Sidebar for API key
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input("Gemini API Key", type="password", help="Enter your Google Gemini API key")
    st.markdown("---")
    st.markdown("### How to use:")
    st.markdown("1. Enter your Gemini API key")
    st.markdown("2. Ask in natural language (e.g., 'Scan IPs from 192.168.1.1 to 192.168.1.50')")
    st.markdown("3. Click 'Analyze and Scan'")
    st.markdown("---")
    timeout_setting = st.slider("Connection Timeout (seconds)", 0.5, 5.0, 1.0, 0.5)
    max_workers = st.slider("Max Concurrent Scans", 10, 100, 50, 10)

# Tool definition for Gemini
TOOL_DEFINITION = {
    "function_declarations": [
        {
            "name": "scan_ip_range",
            "description": "Scans a range of IP addresses to find which ones are open/reachable",
            "parameters": {
                "type": "object",
                "properties": {
                    "start_ip": {
                        "type": "string",
                        "description": "The starting IP address of the range (e.g., '192.168.1.1')"
                    },
                    "end_ip": {
                        "type": "string",
                        "description": "The ending IP address of the range (e.g., '192.168.1.254')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port to check (default is 80 for HTTP)",
                        "default": 80
                    }
                },
                "required": ["start_ip", "end_ip"]
            }
        }
    ]
}

def check_ip_open(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """Check if an IP is reachable on a specific port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except:
        return False

def scan_ip_range(start_ip: str, end_ip: str, port: int = 80, timeout: float = 1.0, max_workers: int = 50) -> Dict[str, Any]:
    """Scan a range of IPs and return open ones"""
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        if start > end:
            return {"error": "Start IP must be less than or equal to end IP"}
        
        ip_list = [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1)]
        total_ips = len(ip_list)
        
        open_ips = []
        closed_ips = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_ip_open, str(ip), port, timeout): ip for ip in ip_list}
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, future in enumerate(as_completed(futures)):
                ip = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ips.append(str(ip))
                    else:
                        closed_ips.append(str(ip))
                except Exception as e:
                    closed_ips.append(str(ip))
                
                progress = (i + 1) / total_ips
                progress_bar.progress(progress)
                status_text.text(f"Scanning: {i + 1}/{total_ips} IPs checked")
            
            progress_bar.empty()
            status_text.empty()
        
        return {
            "total_scanned": total_ips,
            "open_count": len(open_ips),
            "closed_count": len(closed_ips),
            "open_ips": open_ips,
            "port": port,
            "start_ip": start_ip,
            "end_ip": end_ip
        }
    except Exception as e:
        return {"error": str(e)}

def call_gemini_with_tools(query: str, api_key: str) -> Dict[str, Any]:
    """Call Gemini API with function calling"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    headers = {"Content-Type": "application/json"}
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": query}
                ]
            }
        ],
        "tools": [TOOL_DEFINITION]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# Main interface
user_query = st.text_area(
    "Enter your query in natural language:",
    placeholder="Example: Find all open IPs between 192.168.1.1 and 192.168.1.100\nOr: Scan network from 10.0.0.1 to 10.0.0.50 on port 22",
    height=100
)

if st.button("🚀 Analyze and Scan", type="primary"):
    if not api_key:
        st.error("⚠️ Please enter your Gemini API key in the sidebar!")
    elif not user_query:
        st.error("⚠️ Please enter a query!")
    else:
        with st.spinner("🤖 Asking Gemini AI to interpret your query..."):
            gemini_response = call_gemini_with_tools(user_query, api_key)
        
        if "error" in gemini_response:
            st.error(f"❌ Error calling Gemini: {gemini_response['error']}")
        else:
            try:
                # Extract function call from Gemini response
                candidates = gemini_response.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    
                    function_call = None
                    for part in parts:
                        if "functionCall" in part:
                            function_call = part["functionCall"]
                            break
                    
                    if function_call:
                        st.success("✅ Gemini understood your query!")
                        
                        func_name = function_call.get("name")
                        func_args = function_call.get("args", {})
                        
                        with st.expander("🔍 Interpreted Parameters"):
                            st.json(func_args)
                        
                        if func_name == "scan_ip_range":
                            start_ip = func_args.get("start_ip")
                            end_ip = func_args.get("end_ip")
                            port = func_args.get("port", 80)
                            
                            st.info(f"📡 Scanning IP range: {start_ip} to {end_ip} on port {port}")
                            
                            start_time = time.time()
                            result = scan_ip_range(start_ip, end_ip, port, timeout_setting, max_workers)
                            elapsed_time = time.time() - start_time
                            
                            if "error" in result:
                                st.error(f"❌ Scan error: {result['error']}")
                            else:
                                st.success(f"✅ Scan completed in {elapsed_time:.2f} seconds!")
                                
                                # Display metrics
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("Total IPs Scanned", result['total_scanned'])
                                with col2:
                                    st.metric("Open IPs", result['open_count'], delta=f"{result['open_count']}")
                                with col3:
                                    st.metric("Closed IPs", result['closed_count'])
                                
                                # Display open IPs
                                if result['open_ips']:
                                    st.subheader("🟢 Open IP Addresses:")
                                    for ip in result['open_ips']:
                                        st.code(ip)
                                else:
                                    st.warning("No open IPs found in the specified range.")
                    else:
                        st.warning("⚠️ Gemini didn't call the scan function. Try rephrasing your query.")
                        
                        # Show what Gemini said
                        if parts and "text" in parts[0]:
                            st.info(f"Gemini's response: {parts[0]['text']}")
                else:
                    st.error("❌ Unexpected response format from Gemini")
            except Exception as e:
                st.error(f"❌ Error processing response: {str(e)}")
                st.json(gemini_response)

# Examples section
with st.expander("💡 Example Queries"):
    st.markdown("""
    - "Scan IPs from 192.168.1.1 to 192.168.1.50"
    - "Find open hosts between 10.0.0.1 and 10.0.0.100"
    - "Check which IPs are reachable from 172.16.0.1 to 172.16.0.20 on port 22"
    - "Scan network range 192.168.0.100 to 192.168.0.150 on port 443"
    """)

st.markdown("---")
st.caption("⚡ Powered by Google Gemini AI | Built with Streamlit")
