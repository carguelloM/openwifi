import numpy as np
import matplotlib.pyplot as plt

def parse_openwifi_iq_txt(iq_cap_filename="iq.txt"):
    """
    Parse an OpenWiFi iq.txt capture automatically (no hard-coded iq_len).
    Returns:
        rssi_half_db  : (iq_len, n_caps)
        ch_idle_final : (iq_len, n_caps)
        iq_len        : inferred iq_len
    """
    a = np.loadtxt(iq_cap_filename, dtype=np.uint16)
    len_a = (len(a) // 4) * 4
    a = a[:len_a]
    b = a.reshape((-1, 4))  # 4 columns per word group

    # Automatically infer iq_len from total rows
    iq_len = None
    for iq_len_try in range(512, 20000):
        if (b.shape[0] % (1 + iq_len_try)) == 0:
            iq_len = iq_len_try
            break
    if iq_len is None:
        raise ValueError("Couldn't infer iq_len automatically")

    num_per_cap = 1 + iq_len
    n_caps = b.shape[0] // num_per_cap

    rssi_half_db = np.zeros((iq_len, n_caps), dtype=np.float32)
    ch_idle_final = np.zeros((iq_len, n_caps), dtype=np.uint8)

    for i in range(n_caps):
        sp = i * num_per_cap
        rows = b[sp + 1 : sp + num_per_cap, :]

        # rssi_half_db = lower 11 bits of word4
        rssi_half_db[:, i] = (rows[:, 3] & 0x07FF).astype(np.float32)
        # ch_idle_final = bit 15 of word3
        ch_idle_final[:, i] = ((rows[:, 2] & 0x8000) >> 15).astype(np.uint8)

    return rssi_half_db, ch_idle_final, iq_len


def idle_baseline(iq_cap_filename="iq.txt", n_samples=None, plot=True):
    """
    Compute idle baseline using all samples unless n_samples is specified.
    """
    rssi_half_db, ch_idle, iq_len = parse_openwifi_iq_txt(iq_cap_filename)
    print(f"Detected iq_len = {iq_len}")

    # Flatten MATLAB-style
    rssi_vec = rssi_half_db.flatten(order="F")
    idle_vec = ch_idle.flatten(order="F")

    # If n_samples not given, use everything that’s there
    if n_samples is None or n_samples > len(rssi_vec):
        n_samples = len(rssi_vec)
        print(f"Using all {n_samples} samples")

    # Slice accordingly
    rssi_first = rssi_vec[:n_samples]
    idle_first = idle_vec[:n_samples]

    sel = (idle_first == 1) & (rssi_first > 0)
    if not np.any(sel):
        raise RuntimeError("No idle samples found.")

    idle_half_db = float(np.median(rssi_first[sel]))
    print(f"Estimated idle (low) half-RSSI ≈ {idle_half_db:.1f}")

    if plot:
        plt.figure(figsize=(10,3))
        plt.plot(rssi_first, alpha=0.7)
        plt.plot(np.where(sel, rssi_first, np.nan), "k.", alpha=0.4, label="idle points")
        plt.axhline(idle_half_db, color="r", ls="--", label=f"idle ≈ {idle_half_db:.1f}")
        plt.xlabel("Sample index")
        plt.ylabel("Half-RSSI")
        plt.legend(); plt.tight_layout(); plt.show()

    return idle_half_db


def main():
    filename = "iq.txt"
    idle_val = idle_baseline(filename, n_samples=None, plot=True)
    print(f"\nFinal idle baseline (half-RSSI): {idle_val:.2f}")

if __name__ == "__main__":
    main()
