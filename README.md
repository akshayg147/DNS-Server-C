Flow of program:

1. **Client sends a DNS query** (e.g., `google.com` A record).  
2. **DNS server receives the query** on **UDP port 2053**.  
3. **Cache Lookup:**  
   - If the record is **cached and valid**, return the cached response.  
   - If **not cached or expired**, proceed to step 4.  
4. **Forward Query to an Upstream DNS Server** (e.g., `8.8.8.8`):  
   - Sends the original query.  
   - Waits for a response (timeout: **3 seconds**).  
5. **Receive and Validate Response:**  
   - If valid, **cache the response** for future queries.  
   - Return the response to the client.  
6. **Client Receives Response:**  
   - Query resolution is complete.  
