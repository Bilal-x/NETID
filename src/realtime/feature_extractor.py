def extract_features(packet):
    """
    Attempt to extract as many NSL-KDD features as possible from a single packet.
    For demonstration, missing features are defaulted.
    """
    try:
        duration = 0  # duration is a flow-level stat, use 0 per-packet
        protocol_type = str(packet.proto) if hasattr(packet, 'proto') else 'tcp'
        service = 'http'  # Can't infer from general packet; set default
        flag = 'SF'  # Default flag state in NSL-KDD
        src_bytes = len(packet.payload) if hasattr(packet, 'payload') else 0
        dst_bytes = 0  # Outbound only, can't determine from one packet
        land = 1 if (hasattr(packet, 'src') and hasattr(packet, 'dst') and packet.src == packet.dst) else 0
        wrong_fragment = 0
        urgent = 0
        hot = 0
        num_failed_logins = 0
        logged_in = 0
        num_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_host_login = 0
        is_guest_login = 0
        count = 0
        srv_count = 0
        serror_rate = 0
        srv_serror_rate = 0
        rerror_rate = 0
        srv_rerror_rate = 0
        same_srv_rate = 0
        diff_srv_rate = 0
        srv_diff_host_rate = 0
        dst_host_count = 0
        dst_host_srv_count = 0
        dst_host_same_srv_rate = 0
        dst_host_diff_srv_rate = 0
        dst_host_same_src_port_rate = 0
        dst_host_srv_diff_host_rate = 0
        dst_host_serror_rate = 0
        dst_host_srv_serror_rate = 0
        dst_host_rerror_rate = 0
        dst_host_srv_rerror_rate = 0

        # Compose feature list in exact NSL-KDD order (labels and 'difficulty' excluded)
        features = [
            duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
            wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised,
            root_shell, su_attempted, num_root, num_file_creations, num_shells,
            num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count,
            srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate,
            same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
            dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
            dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate,
            dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate
        ]
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None
