import numpy as np
import pyshark
import asyncio

def smith_waterman(seq1, seq2, match=3, mismatch=-3, gap=-2):
    """
    Smith-Waterman algorithm for local sequence alignment.
    """
    rows, cols = len(seq1) + 1, len(seq2) + 1
    score_matrix = np.zeros((rows, cols))
    traceback = np.zeros((rows, cols), dtype=int)

    max_score = 0
    max_pos = None

    for i in range(1, rows):
        for j in range(1, cols):
            match_score = match if seq1[i - 1] == seq2[j - 1] else mismatch
            score = max(
                0,
                score_matrix[i - 1, j - 1] + match_score,
                score_matrix[i - 1, j] + gap,
                score_matrix[i, j - 1] + gap,
            )
            score_matrix[i, j] = score

            if score > max_score:
                max_score = score
                max_pos = (i, j)

            if score == score_matrix[i - 1, j - 1] + match_score:
                traceback[i, j] = 1  # Diagonal
            elif score == score_matrix[i - 1, j] + gap:
                traceback[i, j] = 2  # Up
            elif score == score_matrix[i, j - 1] + gap:
                traceback[i, j] = 3  # Left

    align1, align2 = "", ""
    i, j = max_pos

    while traceback[i, j] != 0:
        if traceback[i, j] == 1:
            align1 = seq1[i - 1] + align1
            align2 = seq2[j - 1] + align2
            i -= 1
            j -= 1
        elif traceback[i, j] == 2:
            align1 = seq1[i - 1] + align1
            align2 = "-" + align2
            i -= 1
        elif traceback[i, j] == 3:
            align1 = "-" + align1
            align2 = seq2[j - 1] + align2
            j -= 1

    return max_score, align1, align2, max_pos

def extract_features_from_pcapng(file_path):
    """
    Extract features from the pcapng file using pyshark.
    Each packet's information can be represented as a tuple (src_ip, dst_ip, protocol, length).
    """
    cap = pyshark.FileCapture(file_path, use_json=True, include_raw=True)
    features = []
    try:
        cap.load_packets()
        for packet in cap:
            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.ip.proto
                length = packet.length
                features.append((src_ip, dst_ip, protocol, length))
            except AttributeError:
                # Handle packets that might not have IP layers
                continue
    except Exception as e:
        print(f"Error processing packets: {e}")
    finally:
        cap.close()
    return features

def main():
    file_path = 'output_part_00020_20240510221237.pcap'
    features = extract_features_from_pcapng(file_path)

    # Convert tuples to strings for alignment
    sequence_str = ''.join([str(f) for f in features])
    attack_pattern = [(192, 168, 1, 100), (192, 168, 1, 101), 6, 60]
    attack_pattern_str = ''.join([str(f) for f in attack_pattern])

    # Perform alignment
    score, align1, align2, max_pos = smith_waterman(sequence_str, attack_pattern_str)

    print(f"Alignment score: {score}")
    print(f"Position of attack: {max_pos}")
    print(f"Alignment:\n{align1}\n{align2}")

if __name__ == "__main__":
    main()
