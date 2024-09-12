# Computer Network Final Assignment
## Project Objective
This project involves setting up various network clients and servers. The main components are:

*  DHCP Server: Provides network configuration information to clients.
*  DNS Server: Resolves domain names to IP addresses.
*  Application Server (APP): Acts as a proxy, retrieving images from a SERVER and delivering them to clients.
*  Client: Interacts with the DHCP, DNS, and APP servers to request and receive images.

## Workflow
1. Client requests network configuration from the DHCP server.
2. Client queries the DNS server to obtain the IP address of the APP.
3. Client interacts with the APP to request an image.
4. APP retrieves the image path from the SERVER and sends the image to the Client.

## Running the Program
### Prerequisites
The code is intended to run in an Ubuntu environment.
Ensure you have Python installed and set up properly.
### Files
1. DHCP.py - DHCP server script.
2. DNS.py - DNS server script.
3. APP.py - Application server (proxy) script.
4. SERVER.py - Image server script.
5. client.py - Client script.
6. image_TCP.jpg - Image for TCP protocol.
7. image_UDP.jpg - Image for UDP protocol.

## Steps to Run
1. Open five separate terminals in the directory where the files are located.
2. In each terminal, execute one of the following commands:
```bash
sudo python <filename>.py
```
Replace <filename> with the appropriate file names from 1 to 5.
3. Run the client last:
```bash
sudo python client.py
```
4. The client will prompt you to enter T for TCP or U for UDP.
5. After receiving the image, the client will prompt you to enter C to request another image or E to exit.
6. After closing the client, you can stop the servers by pressing Ctrl+C in their respective terminals.

## General Explanation

### DHCP Server

*   **Function**: Assigns IP addresses and provides network configuration to clients.
*   **Protocol**: UDP
*   **IP Range**: 10.0.0.17 - 10.0.0.254 (If the range is exhausted, returns "0.0.0.0")
*   **Process**:
    *   **Client → DHCP**: DISCOVER
    *   **DHCP → Client**: OFFER
    *   **Client → DHCP**: REQUEST
    *   **DHCP → Client**: ACK

### DNS Server

*   **Function**: Resolves domain names to IP addresses.
*   **Protocol**: UDP
*   **Process**:
    *   **Client → DNS**: Query
    *   **DNS → Client**: Response (or "0.0.0.0" if domain is not found)

### Application (APP)

*   **Function**: Acts as a proxy, forwarding image requests from the client to the server.
*   **Protocol**:
    *   **Client → APP**: UDP/TCP (based on user choice)
    *   **APP → SERVER**: TCP
*   **Process**:
    *   **Client → APP**: Request for an image
    *   **APP → SERVER**: Request for image path
    *   **SERVER → APP**: Send image path
    *   **APP → Client**: Send image

### Additional Information

* A video demonstration:

https://github.com/user-attachments/assets/d92910f7-e298-4da6-a4c4-5d21fc51dd77

## Contributors
*  <a href="https://github.com/MoriyaEster">Moriya Ester ohayon</a>
*  <a href="https://github.com/ofekats">Ofek Kats</a>
