# Paqet Tunnel Deployment Script

Don't forget to star this repository! ⭐
 
A simple, automated script to deploy a direct tunnel between Iran (Client) and Kharej/External (Server) using **paqet** in **KCP** mode.

## 🚀 Quick Install (Linux)

Run the following command on both your **Iranian** and **External** servers:

```bash
curl -fsSL https://raw.githubusercontent.com/ChownYourLife/paqet-tunnel/master/deploy-tunnel.sh -o deploy.sh && chmod +x deploy.sh && sudo ./deploy.sh
```

### Optional: Install as System Command

After running the script once, you can install it globally to use the `paqet` command anywhere:

```bash
sudo ./deploy.sh --install
```

Now you can simply run:

```bash
sudo paqet              # Open main menu
sudo paqet --status     # List all tunnels
sudo paqet --manage     # Open management menu
sudo paqet --update-core # Update paqet core to latest release
sudo paqet --help       # Show all options
```

To uninstall: `sudo paqet --uninstall`

## ✨ What This Script Does

1.  **Auto-Detects Architecture**: Automatically checks your CPU architecture (AMD64, ARM64, etc.) to download the correct binary.
2.  **Downloads Latest Paqet**: Fetches the latest release of `paqet` directly from its official repository.
3.  **Encrypted Tunneling**:
    - Generates or accepts an **Encryption Key** to secure the connection.
    - Uses **KCP protocol** over raw TCP to bypass firewall restrictions and interruptions.
4.  **Flexible Configuration**:
    - **Modes**: Sets up either a **Server** (Kharej) or a **Client** (Iran).
    - **Performance Tuning**: Allows selecting KCP modes (`fast`, `fast2`, `fast3`) and number of parallel connections for optimized speed.
    - **Proxy Options**:
      - **SOCKS5 Proxy**: Creates a standard SOCKS5 proxy on `127.0.0.1:1080`.
      - **Port Forwarding**: Directly forwards a local port to a remote destination (e.g., forwarding local `8080` to `google.com:80`).
5.  **Service Management**: Creates a `systemd` service so the tunnel runs automatically in the background and restarts on boot.
6.  **Firewall Configuration**: Automatically applies `iptables` rules to ensure traffic flows correctly without kernel interference.

## ⚙️ How to Use

1.  **Run the script** on your External (Kharej) server first.
    - Select **Server** mode.
    - Note the **Encryption Key** generated (or provide your own).
    - Note the **Port** used.

2.  **Run the script** on your Internal (Iran) client machine.
    - Select **Client** mode.
    - Enter the IP address and Port of your External server.
    - Enter the **SAME Encryption Key** used on the server.
    - Choose your connection settings (Proxy type, Connection count, KCP mode).

3.  **Enjoy!**
    - If you chose **SOCKS5**, configure your browser or apps to use `127.0.0.1:1080` as the proxy.
    - If you chose **Port Forwarding**, connect to your specified local port.

## 💖 Donate

If you find this project useful, consider supporting its development:

| Currency | Network      | Address                                        |
| -------- | ------------ | ---------------------------------------------- |
| **USDT** | BEP-20 (BSC) | `0xd729ad31f2709696fd0a368cfa00ecd99bc483d2`   |
| **USDC** | Solana       | `4KWuoheDU5ki1NfTuUyPfAi3cfatREtZ8UV4eZUrKWfX` |

Thank you for your support! 🙏

## 📚 Credits & Sources

- **Paqet** - The core tunneling binary  
  🔗 [hanselime/paqet](https://github.com/hanselime/paqet)

- **KCP Protocol** - Fast and reliable ARQ protocol  
  🔗 [skywind3000/kcp](https://github.com/skywind3000/kcp)

## 📄 License

This deployment script is provided as-is for educational and personal use.
