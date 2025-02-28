import pyshark
import numpy as np

def needleman_wunsch(seq1, seq2, match=2, mismatch=-1, gap=-2):
    rows, cols = len(seq1)+1, len(seq2)+1
    scoring_matrix = np.zeros((rows, cols))
    traceback_matrix = np.zeros((rows, cols), dtype=str)

    for i in range(rows):
        scoring_matrix[i][0] = i * gap
        traceback_matrix[i][0] = "U"  # Up (gap in seq2)
    for j in range(cols):
        scoring_matrix[0][j] = j * gap
        traceback_matrix[0][j] = "L"  # Left (gap in seq1)

    traceback_matrix[0][0] = " "

    for i in range(1, rows):
        for j in range(1, cols):
            char_match = match if seq1[i-1] == seq2[j-1] else mismatch
            scores = [
                scoring_matrix[i-1][j-1] + char_match, 
                scoring_matrix[i-1][j] + gap,           # Up (gap in seq2)
                scoring_matrix[i][j-1] + gap            # Left (gap in seq1)
            ]
            scoring_matrix[i][j] = max(scores)
            traceback_matrix[i][j] = ["D", "U", "L"][scores.index(max(scores))]

    aligned_seq1, aligned_seq2 = "", ""
    i, j = rows-1, cols-1
    while i > 0 or j > 0:
        if traceback_matrix[i][j] == "D":
            aligned_seq1 = seq1[i-1] + aligned_seq1
            aligned_seq2 = seq2[j-1] + aligned_seq2
            i, j = i-1, j-1
        elif traceback_matrix[i][j] == "U":
            aligned_seq1 = seq1[i-1] + aligned_seq1
            aligned_seq2 = "-" + aligned_seq2
            i = i-1
        elif traceback_matrix[i][j] == "L":
            aligned_seq1 = "-" + aligned_seq1
            aligned_seq2 = seq2[j-1] + aligned_seq2
            j = j-1

    return scoring_matrix[-1][-1], aligned_seq1, aligned_seq2

def extract_traffic_details(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    traffic_sequences = []
    try:
        for pkt in cap:
            if 'IP' in pkt:
                src = pkt.ip.src
                dst = pkt.ip.dst
                proto = pkt.highest_layer
                traffic_sequences.append(f"{src}-{dst}-{proto}")
    finally:
        cap.close()
    return traffic_sequences

def analyze_pcap_needleman(pcap_file):
    traffic_sequences = extract_traffic_details(pcap_file)

    if len(traffic_sequences) >= 2:
        seq1 = traffic_sequences[0]
        seq2 = traffic_sequences[1]
        score, aligned_seq1, aligned_seq2 = needleman_wunsch(seq1, seq2)
        print(f"Global Alignment Score: {score}")
        print(f"Aligned Sequence 1: {aligned_seq1}")
        print(f"Aligned Sequence 2: {aligned_seq2}")
    else:
        print("Not enough traffic sequences to compare.")


pcap_path = "C:/Users/eveli/Desktop/small_fileA_00101_20250105224340.pcap"
analyze_pcap_needleman(pcap_path)
