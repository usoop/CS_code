## cicflowmeter
### src_ip
Source IP address string representation.
### dst_ip
Destination IP address string representation.
### src_port
Transport layer source port.
### dst_port
Transport layer destination port.
### protocol
Transport layer protocol.
### timestamp
timestamp
### flow_duration
Duration of the flow in Microsecond
### flow_byts_s
Number of flow bytes per second
### flow_pkts_s
Number of flow packets per second
### fwd_pkts_s
Number of forward packets per second
### bwd_pkts_s
Number of backward packets per second
### tot_fwd_pkts
Total packets in the forward direction
### tot_bwd_pkts
Total packets in the backward direction
### totlen_fwd_pkts
Total size of packet in forward direction
### totlen_bwd_pkts
Total size of packet in backward direction
### fwd_pkt_len_max
Maximum size of packet in forward direction
### fwd_pkt_len_min
Minimum size of packet in forward direction
### fwd_pkt_len_mean
Mean size of packet in forward direction
### fwd_pkt_len_std
Standard deviation size of packet in forward direction
### bwd_pkt_len_max
Maximum size of packet in backward direction
### bwd_pkt_len_min
Minimum size of packet in backward direction
### bwd_pkt_len_mean
Mean size of packet in backward direction
### bwd_pkt_len_std
Standard deviation size of packet in backward direction
### pkt_len_max
Maximum length of a packet
### pkt_len_min
Minimum length of a packet
### pkt_len_mean
Mean length of a packet
### pkt_len_std
Standard deviation length of a packet
### pkt_len_var
Variance length of a packet
### pkt_len_var 
Variance length of a packet
### fwd_header_len
Total bytes used for headers in the forward direction
### bwd_header_len
Total bytes used for headers in the backward direction
### fwd_seg_size_min
Minimum segment size observed in the forward direction
### fwd_act_data_pkts
Count of packets with at least 1 byte of TCP data payload in the forward direction
### flow_iat_mean
Mean time between two packets sent in the flow
### flow_iat_max
Maximum time between two packets sent in the flow
### flow_iat_min
Minimum time between two packets sent in the flow
### flow_iat_std
Standard deviation time between two packets sent in the flow
### fwd_iat_tot
Total time between two packets sent in the forward direction
### fwd_iat_max
Maximum time between two packets sent in the forward direction
### fwd_iat_min
Minimum time between two packets sent in the forward direction
### fwd_iat_mean
Mean time between two packets sent in the forward direction
### fwd_iat_std
Standard deviation time between two packets sent in the forward direction
### bwd_iat_tot
Total time between two packets sent in the backward direction
### bwd_iat_max
Maximum time between two packets sent in the backward direction
### bwd_iat_min
Minimum time between two packets sent in the backward direction
### bwd_iat_mean
Mean time between two packets sent in the backward direction
### bwd_iat_std
Standard deviation time between two packets sent in the backward direction
### fwd_psh_flags
Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
### bwd_psh_flags
Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
### fwd_urg_flags
Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
### bwd_urg_flags
Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)
### fin_flag_cnt
Number of packets with FIN
### syn_flag_cnt
Number of packets with SYN
### rst_flag_cnt
Number of packets with RST
### psh_flag_cnt
Number of packets with PUSH
### ack_flag_cnt
Number of packets with ACK
### urg_flag_cnt
Number of packets with URG
### ece_flag_cnt
Number of packets with ECE
### down_up_ratio
Download and upload ratio
### pkt_size_avg
Average size of packet
### init_fwd_win_byts
The total number of bytes sent in initial window in the forward direction
### init_bwd_win_byts
The total number of bytes sent in initial window in the backward direction
### active_max
Maximum time a flow was active before becoming idle
### active_min
Minimum time a flow was active before becoming idle
### active_mean
Mean time a flow was active before becoming idle
### active_std
Standard deviation time a flow was active before becoming idle
### idle_max
Maximum time a flow was idle before becoming active
### idle_min
Minimum time a flow was idle before becoming active
### idle_mean
Mean time a flow was idle before becoming active
### idle_std
Standard deviation time a flow was idle before becoming active
### fwd_byts_b_avg
Average number of bytes bulk rate in the forward direction
### fwd_pkts_b_avg
Average number of packets bulk rate in the forward direction
### bwd_byts_b_avg
Average number of bytes bulk rate in the backward direction
### bwd_pkts_b_avg
Average number of packets bulk rate in the backward direction
### fwd_blk_rate_avg
Average number of bulk rate in the forward direction
### bwd_blk_rate_avg
Average number of bulk rate in the backward direction
### fwd_seg_size_avg
Average size observed in the forward direction
### bwd_seg_size_avg
Average size observed in the backward direction
### cwe_flag_count
Number of packets with CWE
### subflow_fwd_pkts
The average number of packets in a sub flow in the forward direction
### subflow_bwd_pkts
The average number of packets in a sub flow in the backward direction
### subflow_fwd_byts
The average number of bytes in a sub flow in the forward direction
### subflow_bwd_byts
The average number of bytes in a sub flow in the backward direction
## nfstream
### src_mac
Source MAC address string representation.
### src_oui
Source Organizationally Unique Identifier string representation.
### dst_mac
Destination MAC address string representation.
### dst_oui
Destination Organizationally Unique Identifier string representation.
### ip_version
IP version.
### vlan_id
Virtual LAN identifier.
### bidirectional_first_seen_ms
Timestamp in milliseconds on first flow bidirectional packet.
### bidirectional_last_seen_ms
Timestamp in milliseconds on last flow bidirectional packet.
### src2dst_first_seen_ms
Timestamp in milliseconds on first flow src2dst packet.
### src2dst_last_seen_ms
Timestamp in milliseconds on last flow src2dst packet.
### src2dst_duration_ms
Flow src2dst duration in milliseconds.
### dst2src_first_seen_ms
Timestamp in milliseconds on first flow dst2src packet.
### dst2src_last_seen_ms
Timestamp in milliseconds on last flow dst2src packet.
### dst2src_duration_ms
Flow dst2src duration in milliseconds.
## zeek--conn.log
### ts
Timestamp when the SSL connection was detected
### uid
Unique identifier of connection
### conn_state
Connection state

**State Meaning**
S0:	Connection attempt seen, no reply
S1:	Connection established, not terminated (0 byte counts)
SF:	Normal establish & termination (>0 byte counts)
REJ:	Connection attempt rejected
S2:	Established, ORIG attempts close, no reply from RESP.
S3:	Established, RESP attempts close, no reply from ORIG.
RSTO:	Established, ORIG aborted (RST)
RSTR:	Established, RESP aborted (RST)
RSTOS0:	ORIG sent SYN then RST; no RESP SYN-ACK
RSTRH:	RESP sent SYN-ACK then RST; no ORIG SYN
SH:	ORIG sent SYN then FIN; no RESP SYN-ACK (“half-open”)
SHR:	RESP sent SYN-ACK then FIN; no ORIG SYN
OTH:	No SYN, not closed. Midstream traffic. Partial connection.

### missed_bytes
Number of missing bytes in content gaps
### history
Connection state history

**Letter Meaning**
S:	a SYN without the ACK bit set
H:	a SYN-ACK (“handshake”)
A:	a pure ACK
D:	packet with payload (“data”)
F:	packet with FIN bit set
R:	packet with RST bit set
C:	packet with a bad checksum
I:	Inconsistent packet (Both SYN & RST)
### service
service name
## zeek--http.log
### trans_depth
Pipelined depth into the connection
### method
HTTP Request verb: GET HEAD etc.
### host
Value of the HOST header
### uri
URI used in the request
### version
SSL version that the server offered
### user_agent
Value of the User-Agent header
### request_body_len
Actual uncompressed content size of the data transferred from the client
### response_body_len
Actual uncompressed content size of the data transferred from the server
### status_code
Status code retuened by server
### status_msg
Status message returned by the server
### tags
Indicators of various attributes discovered
### resp_fuids
An ordered vector of file unique IDs from resp
### resp_mime_types
An ordered vector of mime types from resp
### orig_fuids
An ordered vector of file unique IDs from orig
## zeek--weird.log
### weird_name
The name of the weird that occurred
### notice
Indicate if this weird was also turned into a notice
### peer
The peer that generated this weird
## zeek-dns.log
### trans_id
16 bit identifier assigned by DNS client; responses match
### rtt
Round trip time from request to response
### query
Domain name subject of the query
### qclass
Value specifying the query class
### qclass_name
Descriptive name of the query class (e.g. C_INTERNET)
### qtype
Value specifying the query type
### qtype_name
Name of the query type (e.g. A PTR)
### rcode
Response code value in the DNS response
### rcode_name
Descriptive name of the response code 
### AA
Authoritative Answer. T = server is authoritative for query
### TC
Truncation. T = message was truncated
### RD
Recursion Desired. T = request recursive lookup of query
### RA
Recursion Available. T = server supports recursive queries
### Z
Reserved field
### answers
List of resource descriptions in answer to the query
### TTLs
Caching intervals of the answers
### rejected
Whether the DNS query was rejected by the server
## zeek--files.log
### fuid
identifier for a single file
### tx_hosts
if transferred via network
### rx_hosts
if transferred via network
### conn_uids
Connection UID(s) over which the file was transferred
### depth
Depth of file related to source; eg: SMTP MIME
### analyzers
Set of analysis types done during file analysis
### mime_type
Libmagic sniffed file type
### is_orig
If transferred via network
### seen_bytes
Number of bytes provided to file analysis engine
### total_bytes
Total number of bytes that should comprise the file
### missing_bytes
Number of bytes in the file stream missed; eg: dropped packets
### overflow_bytes
Number of not all-in-sequence bytes in the file stream
### timedout
If the file analysis time out at least once per file
### md5/sha1/sha256
MD5/SHA1/SHA256 hash of file
### source
An identification of the source of the file data
## zeek--ssl.log
### cipher
SSL cipher suite that the server chose
### server_name
Value of the Server Name Indicator SSL extension
### resumed
Flag that indicates session was resumed
### established
Flags if SSL session successfully established
### curve
Elliptic curve server chose when using ECDH/ECDHE
### cert_chain_fuids
Ordered vector of all certificate file uniquelDs for certificates offered by server
### client_cert_chain_fuids
Ordered vector of all certificate file uniquelDs for certificates offered by client
### subject
Subject of the X.509 cert offered by the server
### issuer
Subject of signer of X.509 server cert
### issuer_subject
Signer Subject of the cert offered by the server
## zeek--x509.log
### certificate.version
Version number
### certificate.serial
Serial number
### certificate.subject
Subject of X.509 cert offered by server
### certificate.issuer
Certificate issuer
### certificate.not_valid_before
Timestamp before when certificate is not valid
### certificate.not_valid_after
Timestamp after when certificate is not valid
### certificate.key_alg
Name of the key algorithm
### certificate.sig_alg
Name of the signature algorithm
### certificate.key_type
Key type if key parseable openssl (rsa dsa or ec)
### certificate.key_length
Key length in bits
### certificate.exponent
Exponent if RSA-certificate
### san.dns
List of DNS entries in the SAN
### basic_constraints.ca
CA fla set?
### basic_constraints.path_len
Maximum path length
