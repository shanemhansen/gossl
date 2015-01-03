package evp

const (
	EVP_CIPH_STREAM_CIPHER int = 0x0
	EVP_CIPH_ECB_MODE      int = 0x1
	EVP_CIPH_CBC_MODE      int = 0x2
	EVP_CIPH_CFB_MODE      int = 0x3
	EVP_CIPH_OFB_MODE      int = 0x4
	EVP_CIPH_CTR_MODE      int = 0x5
	EVP_CIPH_GCM_MODE      int = 0x6
	EVP_CIPH_CCM_MODE      int = 0x7

	EVP_CIPH_XTS_MODE int = 0x10001
	EVP_CIPH_MODE     int = 0xF0007
)
