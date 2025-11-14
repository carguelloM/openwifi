#include "inject_80211.h"
#include "ieee80211_radiotap.h"

/* This program only works with g and n and only sends data frames 
Look at inject_802.11.c for a program that injects differnet 
types of frames!
*/

#define BUF_SIZE_MAX  128
#define	OFFSET_RATE 0x11
#define MCS_OFFSET 0x19
#define SEQ_NUM_LOW_OFFSET 0x16
#define SEQ_NUM_HIGH_OFFSET 0x17

/* wifi bitrate to use in 500kHz units */
static const u8 u8aRatesToUse[] = {
	6*2, // 1/2 BPSK
	9*2, // 3/4 BPSK
	12*2, // 1/2 QPSK 
	18*2, // 3/4 QPSK
	24*2, // 1/2 16 QAM 
	36*2, // 3/4 16 QAM  
	48*2, // 2/3 64 QAM  
	54*2 //  3/4 64 QAM
};

/* this is the template radiotap header we send packets out with */
static const u8 u8aRadiotapHeader[] = 
{
	0x00, 0x00, // <-- radiotap version
	0x1c, 0x00, // <- radiotap header length
	0x6f, 0x08, 0x08, 0x00, // <-- bitmap
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
	0x00, // <-- flags (Offset +0x10)
	0x6c, // <-- rate (0ffset +0x11)
	0x71, 0x09, 0xc0, 0x00, // <-- channel
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna
	0x00, 0x00, 0x0f,  // <-- MCS
};


/* IEEE80211 header */
static u8 ieee_hdr_data[] =
{
	0x08, 0x02, 0x00, 0x00,             // FC 0x0802. 0--subtype; 8--type&version; 02--toDS0 fromDS1 (data packet from DS to STA)v
	0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // BSSID/MAC of AP
	0x23, 0x23, 0x23, 0x23, 0x23, 0x23, // Transmitter address
	0x23, 0x23, 0x23, 0x23, 0x23, 0x23, // Source address
	0x00, 0x00,                         // 0--fragment number; 0x861=2145--sequence number
};

static u8 llc[] = 
{
	 0xAA, 0xAA, 0x03, // LLC Header
    0x00, 0x00, 0x00, // OUI
    0x00, 0x00,       // Type
};

// generate random payload
void gen_rand_payload(int pyld_len, u8 * pyld)
{

	// srand() must be call in main loop! 
	for (int i=0; i< pyld_len; i++)
	{
		pyld[i] =  (u8)(rand() % 256);
	}
}

int main(int argc , char*argv[])
{
	u8 buffer[BUF_SIZE_MAX];
	u8 rand_pyld[ 69];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int i, nLinkEncap = 0, payld_size=69, nDelay = 100000, ieee_hdr_len = sizeof(ieee_hdr_data);
	int radio_tap_hdr_len = sizeof(u8aRadiotapHeader), rate_index=0;
	pcap_t *pcap_pntr = NULL;



	// open the interface in pcap
	szErrbuf[0] = '\0';
	pcap_pntr = pcap_open_live("sdr0", 800, 1, 20, szErrbuf);

	if (pcap_pntr == NULL)
	{
		printf("Unable to open interface sdr0 in pcap: %s\n", szErrbuf);
		return -1;
	}

	nLinkEncap = pcap_datalink(pcap_pntr);
	switch (nLinkEncap)
	{
		case DLT_PRISM_HEADER:
			printf("DLT_PRISM_HEADER Encap\n");
			break;

		case DLT_IEEE802_11_RADIO:
			printf("DLT_IEEE802_11_RADIO Encap\n");
			break;

		default:
			printf("!!! unknown encapsulation on %s !\n", argv[1]);
			return -2;
	}

	if ( pcap_setnonblock(pcap_pntr, 1, szErrbuf) )
	{
		printf("Error blocking pcap handle: %s", szErrbuf);
		return -3;
	}

	u8 * buf_p = buffer;
	u8 * ieee802;
	int pkt_size = 0;

	memset(buf_p, 0, sizeof(buffer));
	
	// Radio Tap Header
	memcpy(buf_p, u8aRadiotapHeader, radio_tap_hdr_len);
	buf_p[OFFSET_RATE] = u8aRatesToUse[rate_index];
	buf_p += radio_tap_hdr_len;
	pkt_size += radio_tap_hdr_len;

	//80211 HDR
	ieee802 = buf_p;
	memcpy(buf_p, ieee_hdr_data, ieee_hdr_len);
	buf_p += ieee_hdr_len;
	pkt_size += ieee_hdr_len;

	//LLC
	int llc_size = sizeof(llc);
	memcpy(buf_p, llc, llc_size);
	buf_p += llc_size;
	pkt_size +=llc_size;

	srand(42);

	//payload 
	pkt_size += payld_size; // note payload copy happens in the loop

	u16 seq_num = 0;
	u16 seq_field;
	int r;
	printf("About to start pkt injection!\n");
	for(int i=0; i < 10000; i++)
	{
		//update sequence num
		seq_field = seq_num << 4;
		ieee802[SEQ_NUM_LOW_OFFSET] = seq_field & 0xFF;
		ieee802[SEQ_NUM_HIGH_OFFSET] = (seq_field >> 8) & 0xFF;

		// updat payload
		gen_rand_payload(payld_size, rand_pyld);
		memcpy(buf_p, rand_pyld, payld_size);

		// inject packet
		r = pcap_inject(pcap_pntr, buffer, pkt_size);
		if(r != pkt_size)
		{
			perror("Problem with pkt injection\n");
			return -3;
		}
		usleep(nDelay);

		// increment sequence number
		seq_num = (seq_num + 1) & 0x0FFF;   // use only last 12 bits
	}
	printf("Packet Injection Done\n");
}



