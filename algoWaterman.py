import pyshark
import numpy as np

def smith_waterman(seq1, seq2, match=2, mismatch=-1, gap=-2):
    rows, cols = len(seq1)+1, len(seq2)+1
    scoring_matrix = np.zeros((rows, cols))
    max_score = 0
    max_pos = None

    for i in range(1, rows):
        for j in range(1, cols):
            char_match = match if seq1[i-1] == seq2[j-1] else mismatch
            scores = [
                0,
                scoring_matrix[i-1][j-1] + char_match,
                scoring_matrix[i-1][j] + gap,
                scoring_matrix[i][j-1] + gap
            ]
            scoring_matrix[i][j] = max(scores)
            if scoring_matrix[i][j] > max_score:
                max_score = scoring_matrix[i][j]
                max_pos = (i, j)


    aligned_seq1, aligned_seq2 = "", ""
    i, j = max_pos
    while scoring_matrix[i][j] > 0:
        if scoring_matrix[i][j] == scoring_matrix[i-1][j-1] + (match if seq1[i-1] == seq2[j-1] else mismatch):
            aligned_seq1 = seq1[i-1] + aligned_seq1
            aligned_seq2 = seq2[j-1] + aligned_seq2
            i, j = i-1, j-1
        elif scoring_matrix[i][j] == scoring_matrix[i-1][j] + gap:
            aligned_seq1 = seq1[i-1] + aligned_seq1
            aligned_seq2 = "-" + aligned_seq2
            i = i-1
        else:
            aligned_seq1 = "-" + aligned_seq1
            aligned_seq2 = seq2[j-1] + aligned_seq2
            j = j-1

    return max_score, aligned_seq1, aligned_seq2

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

def analyze_pcap(pcap_file):
    traffic_sequences = extract_traffic_details(pcap_file)

    if len(traffic_sequences) >= 2:
        seq1 = traffic_sequences[0]
        seq2 = traffic_sequences[1]
        score, aligned_seq1, aligned_seq2 = smith_waterman(seq1, seq2)
        print(f"Alignment Score: {score}")
        print(f"Sequence 1: {aligned_seq1}")
        print(f"Sequence 2: {aligned_seq2}")
    else:
        print("Not enough traffic sequences to compare.")

pcap_path = "C:/Users/eveli/Desktop/small_fileA_00101_20250105224340.pcap"
analyze_pcap(pcap_path)
