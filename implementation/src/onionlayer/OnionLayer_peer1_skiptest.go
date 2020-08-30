package onionlayer

import (
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"onion/config"
	"strconv"
	"testing"
	"time"
)

func getHostKey(n int) []byte {
	pubkey := make([][]byte, 3)
	pubkey[0] = []byte {
		0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xcf, 0x95, 0x3d, 0x5c, 0xa8, 0x0b, 0xf1,
		0x38, 0x63, 0x5d, 0xdc, 0xdd, 0xdb, 0x91, 0x8b, 0xf6, 0x87, 0x33, 0x57, 0x1e, 0x23, 0x84, 0x64,
		0xfb, 0x4f, 0x19, 0x1c, 0xf6, 0xed, 0x0e, 0xed, 0xf4, 0x88, 0x37, 0x1d, 0x05, 0x03, 0x8c, 0x3c,
		0x24, 0xf8, 0xdd, 0x39, 0xb4, 0x09, 0xc9, 0x16, 0x92, 0xf4, 0x0e, 0xb6, 0xd4, 0x74, 0x13, 0x48,
		0xcb, 0x2b, 0x07, 0x90, 0x3a, 0x36, 0xd3, 0xa4, 0xdb, 0x1d, 0xc3, 0xd6, 0xb2, 0x53, 0x94, 0x08,
		0x03, 0x06, 0x6d, 0x0b, 0xd4, 0xca, 0xce, 0x15, 0x8d, 0x93, 0x91, 0x4c, 0x07, 0xea, 0x58, 0x88,
		0x05, 0x97, 0x9d, 0x46, 0x5b, 0xee, 0xb1, 0x97, 0xfe, 0xe0, 0x05, 0x08, 0x78, 0xde, 0xfe, 0xb3,
		0x86, 0x3d, 0xa8, 0x71, 0xc5, 0xdb, 0x3e, 0xf2, 0xd2, 0x6e, 0x56, 0xf7, 0xb4, 0xb2, 0xed, 0x31,
		0x8e, 0xe3, 0x34, 0xf3, 0xb6, 0xb0, 0x0b, 0xaa, 0xe2, 0xd7, 0x5b, 0x68, 0xae, 0x2e, 0xb5, 0x60,
		0xd8, 0x45, 0x27, 0x64, 0x72, 0x6d, 0x00, 0x25, 0xa6, 0x75, 0x30, 0xa6, 0xef, 0x3e, 0xa5, 0x76,
		0xda, 0xff, 0x8f, 0x0d, 0x8c, 0x8e, 0xe2, 0x94, 0x7f, 0xf6, 0xdf, 0xb2, 0x17, 0x29, 0x91, 0x5c,
		0xfd, 0xb2, 0x21, 0x79, 0x84, 0xac, 0xc0, 0xdb, 0x31, 0x72, 0x27, 0xd0, 0xa2, 0x6d, 0x53, 0x9b,
		0x40, 0x07, 0x88, 0x3c, 0x01, 0x91, 0xee, 0x52, 0xec, 0xcc, 0xd5, 0xd0, 0x89, 0xb8, 0x6b, 0x39,
		0x0e, 0xf8, 0x72, 0x42, 0xce, 0xf0, 0x87, 0xaa, 0x7b, 0xcf, 0x8d, 0x57, 0x38, 0x6f, 0xe4, 0x10,
		0x89, 0xe5, 0x47, 0xa3, 0x9d, 0x57, 0x50, 0x92, 0x07, 0x69, 0x15, 0xd0, 0xed, 0xa8, 0x4b, 0x78,
		0x26, 0x0c, 0x17, 0x36, 0x37, 0x5c, 0x30, 0x7a, 0xd9, 0xae, 0x25, 0x31, 0x3c, 0x28, 0x3f, 0x8f,
		0xf0, 0xfa, 0xdb, 0x93, 0xe7, 0x58, 0xe4, 0x37, 0x2a, 0xbb, 0x16, 0x0c, 0x3d, 0xf2, 0xe0, 0xd8,
		0xa4, 0xa4, 0x70, 0x79, 0x11, 0x79, 0x65, 0xab, 0x86, 0xc1, 0xc5, 0x2a, 0xd4, 0xec, 0xd6, 0x33,
		0xe0, 0xb4, 0xf9, 0x77, 0xaf, 0xf4, 0x67, 0x84, 0xea, 0x65, 0x62, 0xe1, 0x42, 0xc9, 0x34, 0x38,
		0xd9, 0xce, 0xe4, 0xb3, 0x7b, 0x7b, 0x21, 0x64, 0x64, 0x10, 0xf3, 0xe1, 0xd7, 0x6a, 0xc5, 0x2d,
		0x0e, 0xdb, 0x74, 0x1f, 0xc4, 0x47, 0xe9, 0xa4, 0x75, 0xf8, 0x8a, 0xfc, 0xa4, 0x8b, 0x6b, 0x8a,
		0x56, 0xee, 0xe1, 0x74, 0x51, 0xf8, 0xb8, 0xff, 0x40, 0xee, 0xb1, 0xc9, 0xdd, 0x25, 0xa3, 0x75,
		0x03, 0xed, 0xee, 0xf5, 0x1f, 0xf6, 0x42, 0x4c, 0xe9, 0x0f, 0x31, 0x67, 0x85, 0xf7, 0x6e, 0xc4,
		0x42, 0x70, 0x8c, 0x17, 0xdf, 0x09, 0xe2, 0xa8, 0xdd, 0x08, 0x2a, 0xd9, 0x17, 0xb1, 0x90, 0x3b,
		0xd3, 0x08, 0xa2, 0x4a, 0xba, 0x6f, 0x0c, 0x3e, 0xa1, 0xda, 0xb0, 0x35, 0xbe, 0xb4, 0x7f, 0xf6,
		0x7a, 0x28, 0x8a, 0xd7, 0x0b, 0x27, 0xfb, 0x6b, 0xe4, 0x85, 0xa5, 0x00, 0x10, 0x42, 0xa7, 0xdc,
		0x4a, 0x14, 0xb7, 0x5f, 0x22, 0x44, 0x18, 0xae, 0x57, 0x80, 0x62, 0xdb, 0x8a, 0x29, 0xcc, 0x12,
		0xd3, 0xcd, 0x79, 0x5a, 0x2f, 0x3a, 0x02, 0xbe, 0x49, 0x2c, 0xb5, 0x2f, 0x62, 0x39, 0x06, 0xcd,
		0x1e, 0x4f, 0xb7, 0xd8, 0x24, 0xfd, 0xd6, 0xc5, 0x98, 0x78, 0xf4, 0x27, 0xff, 0x01, 0x75, 0x3b,
		0x83, 0xbd, 0x98, 0x4a, 0x5a, 0x67, 0x14, 0xda, 0xfb, 0xd5, 0x11, 0xd2, 0xa3, 0x77, 0x83, 0x41,
		0x3c, 0x01, 0x07, 0xf3, 0x9b, 0xd8, 0x64, 0x8f, 0x56, 0x31, 0xfc, 0x10, 0x98, 0x5d, 0x08, 0xdc,
		0x70, 0x65, 0xb0, 0x46, 0x0d, 0xfe, 0x71, 0x2c, 0xa6, 0x67, 0x55, 0xc3, 0x59, 0x7f, 0xa0, 0xf9,
		0x0a, 0xd8, 0x77, 0x54, 0x86, 0xd5, 0x85, 0xe3, 0x1f, 0x02, 0x03, 0x01, 0x00, 0x01,
	}
	pubkey[1] = []byte {
		0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xb8, 0xce, 0xa6, 0x17, 0xa5, 0xa6, 0x57,
		0x0c, 0xa6, 0x5e, 0xf6, 0xf1, 0x99, 0x84, 0x97, 0x72, 0xa2, 0x7c, 0xf4, 0x26, 0x00, 0x4a, 0x00,
		0x93, 0x7c, 0xf0, 0xd2, 0x53, 0x69, 0xcd, 0xcb, 0xb1, 0xb5, 0xaf, 0x5d, 0x9d, 0x53, 0xf3, 0x66,
		0x44, 0xba, 0x27, 0xdb, 0xb2, 0x55, 0x64, 0xb3, 0xae, 0x1e, 0xaf, 0xc4, 0x68, 0xf2, 0xe2, 0xa8,
		0x26, 0xad, 0x94, 0x04, 0x8f, 0x7b, 0xec, 0x90, 0xd4, 0x80, 0xc3, 0x5d, 0xb8, 0x74, 0x16, 0xd8,
		0x02, 0x8e, 0x75, 0x16, 0x28, 0xa5, 0xe6, 0x54, 0x4f, 0x68, 0xd8, 0x85, 0xd1, 0x70, 0x83, 0xcd,
		0xef, 0x2a, 0xb4, 0xcb, 0x8c, 0xbd, 0x25, 0xe1, 0x68, 0x21, 0x7d, 0x1b, 0x93, 0x6d, 0x9c, 0x24,
		0xd1, 0x77, 0x83, 0xc2, 0x01, 0x45, 0xf1, 0x56, 0xe7, 0xa0, 0xa0, 0x3c, 0xf0, 0xcf, 0x81, 0x85,
		0x1c, 0x64, 0xf5, 0xb1, 0x1d, 0xf8, 0x6e, 0xa2, 0xc0, 0x95, 0x16, 0xe8, 0xe7, 0xd7, 0x5f, 0x4a,
		0x75, 0x69, 0x99, 0x20, 0x31, 0xdf, 0x19, 0xd3, 0xd7, 0xc7, 0x8d, 0x93, 0xb1, 0x72, 0xbb, 0x50,
		0x6f, 0xc0, 0x6b, 0x35, 0xcc, 0xc4, 0x3b, 0xd0, 0x0d, 0xad, 0xb4, 0x4e, 0x15, 0x2f, 0xde, 0x40,
		0x65, 0x57, 0xb7, 0xcf, 0xac, 0x0c, 0xc0, 0x60, 0x7e, 0xca, 0xd3, 0x91, 0x9c, 0x5e, 0xde, 0xc7,
		0x9b, 0xcd, 0x9c, 0xdd, 0x99, 0x16, 0xd5, 0xb9, 0x10, 0x3b, 0x71, 0xde, 0x57, 0x5f, 0x94, 0xe8,
		0x64, 0x23, 0x0f, 0x12, 0x0a, 0xb8, 0x05, 0x64, 0xf6, 0x49, 0x0f, 0x67, 0x5e, 0x33, 0xe0, 0x2c,
		0x1d, 0x47, 0x10, 0x2f, 0x62, 0xb9, 0xce, 0x04, 0xeb, 0xea, 0x6c, 0x79, 0x38, 0x33, 0xed, 0xd3,
		0xd1, 0xbe, 0x87, 0x34, 0xfe, 0xb1, 0x44, 0xb2, 0x34, 0x04, 0x97, 0x43, 0x2c, 0x52, 0xc9, 0x76,
		0xa7, 0xee, 0xc3, 0x02, 0xc9, 0x6d, 0xa4, 0xa3, 0x65, 0x3e, 0xd8, 0xed, 0xb0, 0x54, 0xd4, 0xd5,
		0x20, 0x92, 0x59, 0x57, 0x09, 0xdc, 0x68, 0x01, 0x62, 0x52, 0xc7, 0x0f, 0xdd, 0xca, 0x8d, 0x6c,
		0x5a, 0x87, 0xeb, 0x01, 0x7d, 0x07, 0xff, 0x3c, 0xf1, 0x54, 0xb3, 0x06, 0x82, 0xe2, 0x57, 0xfa,
		0xa7, 0x7b, 0xf0, 0xf2, 0x0b, 0xfa, 0x41, 0x33, 0xa0, 0x8f, 0xfb, 0x1b, 0xc2, 0xc4, 0x34, 0x93,
		0xce, 0x74, 0x39, 0x35, 0xf1, 0xe9, 0xca, 0x53, 0xa8, 0xe6, 0x74, 0xbd, 0x80, 0xac, 0x1b, 0xdc,
		0x8f, 0x7e, 0xd5, 0xd3, 0xc4, 0xdc, 0x28, 0x38, 0x6e, 0xde, 0x07, 0x66, 0x43, 0xe7, 0x96, 0xb3,
		0x99, 0xc5, 0xd4, 0x0f, 0x61, 0xfd, 0xfd, 0x5c, 0x1e, 0xbb, 0x90, 0xbc, 0xf5, 0xeb, 0x5c, 0x61,
		0x4d, 0x1c, 0xd4, 0xcc, 0xdd, 0xff, 0x90, 0xc8, 0x13, 0xb5, 0xcb, 0xf3, 0xa4, 0x00, 0x0b, 0x29,
		0x0a, 0x06, 0xcf, 0xd2, 0x99, 0xf9, 0xe8, 0xc8, 0xa8, 0xc7, 0xdf, 0x1e, 0x2e, 0xa6, 0x90, 0xfe,
		0x1c, 0x4e, 0x0f, 0xcc, 0xac, 0xfb, 0xd0, 0xb9, 0xd8, 0xf3, 0x6f, 0x3b, 0xbb, 0x8a, 0x92, 0xf6,
		0x42, 0x8f, 0x12, 0x5b, 0x47, 0x33, 0x03, 0xef, 0x14, 0x0c, 0x17, 0xe2, 0x42, 0x30, 0x36, 0x03,
		0x5a, 0x56, 0x1e, 0x73, 0x0c, 0xb6, 0xc6, 0xb2, 0x87, 0x4c, 0xa4, 0xca, 0xe9, 0xcf, 0x8e, 0x48,
		0x1e, 0xf5, 0x6d, 0xc2, 0x0d, 0x9e, 0xdd, 0x5c, 0xc9, 0xf9, 0x7c, 0xa1, 0xbd, 0xa4, 0xc8, 0x3f,
		0x82, 0x2a, 0x2b, 0x04, 0x2c, 0x51, 0x6e, 0xec, 0xbd, 0x57, 0xc6, 0x54, 0x95, 0x0e, 0xbd, 0x8a,
		0x65, 0xb4, 0x3a, 0x6e, 0xe7, 0x2f, 0x9e, 0x41, 0x85, 0xcb, 0x7d, 0x29, 0x67, 0x69, 0x55, 0x60,
		0x78, 0x61, 0x13, 0xcf, 0xb9, 0x04, 0x1f, 0x4e, 0x14, 0x27, 0x7b, 0xa3, 0x0c, 0xcc, 0x56, 0x86,
		0x19, 0x23, 0x71, 0x25, 0x46, 0x30, 0x51, 0xa6, 0xa9, 0x02, 0x03, 0x01, 0x00, 0x01,
	}
	pubkey[2] = []byte {
		0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xc6, 0xd3, 0xfd, 0x93, 0xe9, 0x1a, 0xc9,
		0x60, 0x0d, 0xff, 0xd1, 0x83, 0xa0, 0x34, 0x63, 0x11, 0xb4, 0xb8, 0xab, 0x59, 0x39, 0x4d, 0x39,
		0xb3, 0xc1, 0x23, 0x9a, 0xf6, 0x00, 0xd0, 0x3b, 0xd4, 0xaa, 0xf1, 0xcb, 0xb5, 0xab, 0xa5, 0x11,
		0x67, 0x6c, 0x74, 0x47, 0x85, 0xc4, 0x3d, 0xdb, 0x1f, 0x92, 0x97, 0xdf, 0xdb, 0xd1, 0x4a, 0xf6,
		0x82, 0x8c, 0xdd, 0x23, 0x57, 0x9f, 0xfa, 0x72, 0xd7, 0x39, 0x06, 0x38, 0x54, 0x0d, 0xc7, 0xa7,
		0xd5, 0xa9, 0x1c, 0x4d, 0xbf, 0x15, 0x70, 0xb5, 0x27, 0xbc, 0x34, 0x07, 0xd5, 0x30, 0x50, 0x59,
		0x8a, 0x1e, 0xef, 0xc5, 0xcb, 0x8c, 0xa8, 0x22, 0x97, 0x88, 0x05, 0x28, 0xa6, 0xec, 0x09, 0xe1,
		0xbe, 0xb8, 0x0e, 0xbc, 0x56, 0x52, 0x1b, 0xdc, 0xa8, 0x45, 0xb2, 0x28, 0x24, 0xe6, 0x87, 0xf5,
		0xe7, 0xb0, 0xd3, 0xe2, 0x2f, 0xd5, 0xba, 0x01, 0x0b, 0xb3, 0xac, 0xe8, 0x28, 0xb5, 0xea, 0x4b,
		0xef, 0xff, 0x53, 0xf8, 0x4c, 0x88, 0x8d, 0x55, 0xf3, 0x9f, 0xfa, 0xca, 0xfd, 0x73, 0x83, 0x02,
		0x8c, 0x0d, 0x52, 0x7c, 0x03, 0x2d, 0xa9, 0x27, 0x5e, 0x68, 0xb1, 0x54, 0xd5, 0xed, 0xba, 0xb2,
		0x3a, 0xe8, 0x5c, 0x7f, 0x0f, 0x91, 0x75, 0xcc, 0x70, 0xd7, 0x00, 0xcd, 0x97, 0x8a, 0xe2, 0x85,
		0xd3, 0xc9, 0x53, 0xe3, 0xac, 0x44, 0x5e, 0x12, 0xda, 0xe5, 0x87, 0xe4, 0x48, 0xf3, 0x8a, 0xf8,
		0x5c, 0xd1, 0x08, 0x47, 0x37, 0x2b, 0x74, 0xdc, 0xa2, 0xd2, 0xb8, 0x31, 0xca, 0x52, 0x82, 0x45,
		0xbe, 0x7e, 0xbb, 0xde, 0xa4, 0x12, 0x6f, 0xe4, 0x93, 0x4e, 0x68, 0xa4, 0x77, 0xb0, 0x74, 0xe4,
		0xb9, 0xa0, 0xc3, 0x60, 0x58, 0xad, 0x66, 0x32, 0xca, 0xfc, 0x1c, 0x11, 0x41, 0xfa, 0xb8, 0xf7,
		0xfd, 0x9c, 0x72, 0xc9, 0xbc, 0xec, 0x66, 0x58, 0xd1, 0x7b, 0xd6, 0x1a, 0xcd, 0x72, 0xec, 0x57,
		0x6a, 0xaa, 0x9b, 0x83, 0x4a, 0x36, 0x91, 0x63, 0xdf, 0x5a, 0x2b, 0x76, 0x78, 0xdd, 0x2a, 0xae,
		0xdb, 0x80, 0x3c, 0x76, 0xc7, 0xb0, 0x92, 0xf4, 0x6f, 0xfd, 0x91, 0x80, 0xe2, 0xc9, 0x57, 0xac,
		0x09, 0xd8, 0xa0, 0xc6, 0x83, 0x81, 0x82, 0xb6, 0x93, 0xc3, 0xa8, 0x89, 0x52, 0xac, 0x98, 0x13,
		0x40, 0x27, 0xf5, 0x37, 0x42, 0x37, 0x5f, 0x22, 0x99, 0xa8, 0x45, 0x13, 0x14, 0xd8, 0xfc, 0xfa,
		0x93, 0x2c, 0xb0, 0x1f, 0xe9, 0xba, 0x82, 0xa8, 0xb2, 0xff, 0x70, 0x38, 0x2d, 0xe2, 0x6b, 0xb7,
		0x39, 0x5f, 0x83, 0x9e, 0x19, 0xf4, 0x2a, 0xe2, 0x67, 0x9f, 0xfd, 0xc1, 0x7e, 0xbc, 0x1d, 0x8a,
		0x7d, 0xc8, 0xfa, 0xc7, 0xbc, 0x47, 0xf8, 0x69, 0xce, 0x39, 0x6e, 0x1f, 0xab, 0xba, 0x8a, 0x31,
		0xb7, 0xfb, 0x2b, 0x8b, 0xf0, 0xc2, 0x10, 0xb1, 0x87, 0xca, 0x33, 0x0a, 0xd3, 0x80, 0x4d, 0x12,
		0x7e, 0xa8, 0xef, 0xa7, 0x75, 0x85, 0xc4, 0x86, 0x53, 0x0f, 0x05, 0x77, 0xc1, 0xc9, 0x37, 0x87,
		0x30, 0x9f, 0x36, 0x57, 0x61, 0x73, 0x99, 0x8f, 0x75, 0x32, 0xe0, 0x2a, 0xc7, 0x2c, 0x86, 0xbb,
		0x5e, 0x8d, 0x19, 0xb2, 0x4c, 0x05, 0x91, 0x41, 0xf2, 0x90, 0xa6, 0xaa, 0x69, 0x07, 0x56, 0x13,
		0x71, 0x28, 0x34, 0x7b, 0x3e, 0x28, 0x8b, 0xcc, 0xd1, 0x99, 0xa2, 0xf6, 0x6f, 0xda, 0xc7, 0xfd,
		0x2a, 0x26, 0x6d, 0x83, 0x8b, 0xb3, 0x66, 0x87, 0xfe, 0x00, 0x5e, 0x01, 0x39, 0xb2, 0xed, 0x93,
		0x4f, 0x51, 0xb9, 0x01, 0x19, 0xef, 0x3d, 0x33, 0x6a, 0x68, 0x73, 0x06, 0x93, 0x0e, 0xe1, 0x62,
		0x93, 0x1b, 0xa4, 0x7c, 0xc5, 0xe6, 0xd8, 0x81, 0x38, 0x5d, 0xc0, 0x86, 0x1a, 0x46, 0xb6, 0xed,
		0x8d, 0x7b, 0xd6, 0xca, 0xcf, 0x9b, 0xa2, 0xdd, 0x1b, 0x02, 0x03, 0x01, 0x00, 0x01,
	}
	return pubkey[n]
}

func getRspHeader(n int) []byte {
	rspStart := make([][]byte, 3)
	rspStart[0] = []byte {
		0x0, 0x0, 0x2, 0x1d,	// 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0,		// 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe1,	// 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65505) in big endian
		0x7f, 0x0, 0x0, 0x1,	// 4 bytes peer IPv4 address (127.0.0.1)
	}
	rspStart[1] = []byte {
		0x0, 0x0, 0x2, 0x1d,	// 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0,		// 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe2,	// 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65506) in big endian
		0x7f, 0x0, 0x0, 0x1,	// 4 bytes peer IPv4 address (127.0.0.1)
	}
	rspStart[2] = []byte {
		0x0, 0x0, 0x2, 0x1d,	// 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0,		// 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe3,	// 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65506) in big endian
		0x7f, 0x0, 0x0, 0x1,	// 4 bytes peer IPv4 address (127.0.0.1)
	}
	return rspStart[n]
}

func getPeerDetails(n int) []byte {
	pubkey := getHostKey(n)
	rspStart := getRspHeader(n)
	totalLength := len(rspStart) + len(pubkey)
	binary.BigEndian.PutUint16(rspStart[:2], uint16(totalLength))
	fullRsp := make([]byte, totalLength)
	copy(fullRsp[:len(rspStart)], rspStart)
	copy(fullRsp[len(rspStart):totalLength], pubkey)
	return fullRsp
}

func serveRPS(t *testing.T) {
	listenConn, _ := net.Listen("tcp", "localhost:65530")
	defer listenConn.Close()
	counter := 0
	for {
		conn, _ := listenConn.Accept()
		lengthTypeBuf := make([]byte, 4)
		io.ReadFull(conn, lengthTypeBuf)
		rspLength := binary.BigEndian.Uint16(lengthTypeBuf[:2])
		rspType := binary.BigEndian.Uint16(lengthTypeBuf[2:4])
		rspBuf := make([]byte, rspLength - 4)
		io.ReadFull(conn, rspBuf)
		if rspLength != 4 || rspType != 540 {
			t.Errorf("Got malformed RPS request")
			return
		}
		// prepare response
		conn.Write(getPeerDetails(counter))
		conn.Close()
		counter++
	}
}

func TestBuildTunnelSingleHopPeer1(t *testing.T) {
	destinationPublicKeyRaw := []byte {
		0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xa4, 0x86, 0x12, 0x10, 0xf5, 0x2a, 0x5c,
		0x61, 0xc5, 0x3b, 0xce, 0x96, 0x14, 0x76, 0x6b, 0xf1, 0x02, 0xef, 0x58, 0xf0, 0xb2, 0x85, 0x13,
		0xed, 0x0c, 0x08, 0x77, 0x98, 0x29, 0x90, 0x73, 0x5b, 0x41, 0x95, 0x7c, 0xf7, 0x07, 0x36, 0xd5,
		0xf2, 0x86, 0xcd, 0x2a, 0xb6, 0x78, 0xd5, 0x95, 0x7e, 0x9a, 0xcd, 0xcd, 0x52, 0xa0, 0x73, 0xda,
		0x18, 0x4f, 0x18, 0x4a, 0xdb, 0x4d, 0x61, 0x82, 0x61, 0x5a, 0x57, 0x2f, 0xc7, 0xb4, 0x6f, 0xa8,
		0xbd, 0xb8, 0x99, 0x3a, 0x29, 0xa4, 0x6d, 0xab, 0xc8, 0xbd, 0xb6, 0xa0, 0x38, 0xa0, 0x2e, 0x69,
		0xc1, 0xec, 0x73, 0xcd, 0x57, 0xda, 0x88, 0x0b, 0xd4, 0xdb, 0x5d, 0x6b, 0xb9, 0xff, 0xd0, 0xa5,
		0x37, 0xfe, 0x1c, 0xe3, 0x2c, 0x28, 0x9f, 0x36, 0x83, 0xbe, 0x7f, 0x77, 0xa4, 0xc8, 0x58, 0xdf,
		0xf5, 0xf0, 0xeb, 0xf9, 0x12, 0xac, 0x37, 0x74, 0xc0, 0x38, 0xc9, 0x24, 0xaa, 0x3f, 0xba, 0xc7,
		0x83, 0xba, 0xcb, 0x8a, 0x7d, 0x3e, 0x3a, 0xb2, 0x8f, 0x3b, 0x33, 0x39, 0x7e, 0x5b, 0x1b, 0x0c,
		0x8d, 0x52, 0x2a, 0x11, 0xa1, 0xed, 0xa2, 0xb5, 0x50, 0xc9, 0x1b, 0x61, 0x5f, 0x3b, 0x9d, 0x2b,
		0x1e, 0xcb, 0xaf, 0x51, 0xa1, 0x6d, 0xf5, 0xc9, 0xc9, 0xef, 0xeb, 0x5e, 0xb3, 0x02, 0x00, 0x80,
		0xac, 0xbc, 0x84, 0xf3, 0xf7, 0xb2, 0x00, 0xa3, 0x18, 0x74, 0xd1, 0xee, 0xf9, 0xdc, 0x0f, 0x4e,
		0x11, 0x53, 0xa2, 0x4f, 0x9f, 0x97, 0x25, 0xc2, 0x9d, 0xc9, 0x20, 0xde, 0xc3, 0x3f, 0x0b, 0x9a,
		0x73, 0x96, 0x85, 0x33, 0x3c, 0x23, 0x9a, 0xf9, 0x49, 0x51, 0xd1, 0xcf, 0x2f, 0x21, 0x03, 0x4e,
		0x02, 0x1d, 0x39, 0xdf, 0x19, 0xeb, 0x44, 0xcd, 0xad, 0x8e, 0x24, 0x07, 0x6e, 0x7c, 0x6c, 0x36,
		0xc1, 0xee, 0xfb, 0xb3, 0x24, 0x40, 0xc8, 0x42, 0xda, 0x4b, 0x19, 0x13, 0xe7, 0xcc, 0x75, 0x1f,
		0x08, 0x03, 0xfb, 0x8b, 0x83, 0xc9, 0xf4, 0x21, 0x7d, 0xb3, 0xaf, 0x6b, 0xa7, 0xa4, 0xd6, 0xed,
		0x14, 0x50, 0x7a, 0x26, 0x76, 0x07, 0xae, 0x95, 0x85, 0xfd, 0xaa, 0x6b, 0x52, 0x18, 0x77, 0xcb,
		0x98, 0xf6, 0xbe, 0xa3, 0xfe, 0x78, 0x11, 0x18, 0xf0, 0x96, 0x89, 0x18, 0x06, 0xa6, 0xa7, 0xb3,
		0xf8, 0xe2, 0xca, 0xb4, 0x37, 0x55, 0x8c, 0xd8, 0x61, 0xf1, 0x55, 0xcb, 0xf8, 0x59, 0x1f, 0xb4,
		0xcb, 0x27, 0xb2, 0x33, 0xe0, 0xe4, 0x56, 0xb0, 0x4b, 0x4e, 0xc1, 0x20, 0xdb, 0x26, 0xc3, 0x77,
		0xd0, 0xf9, 0x5b, 0x3a, 0x5e, 0x42, 0x97, 0x22, 0x29, 0x46, 0x4a, 0xe6, 0x3a, 0x98, 0x94, 0x30,
		0xea, 0xd5, 0xfd, 0xa0, 0x18, 0x1b, 0x6e, 0x47, 0x85, 0x85, 0x05, 0x09, 0x4c, 0x8c, 0x6a, 0x4d,
		0x63, 0x8f, 0xec, 0xbf, 0x08, 0x22, 0x9e, 0xbf, 0xa3, 0x44, 0x4c, 0xf7, 0x44, 0x6c, 0x58, 0xe3,
		0x17, 0x00, 0xba, 0x2b, 0x82, 0x62, 0x04, 0x22, 0x39, 0x57, 0x03, 0xdd, 0x1d, 0xf6, 0x35, 0x01,
		0x1a, 0xa8, 0xbb, 0x33, 0x6c, 0x93, 0x55, 0xc4, 0x25, 0xe4, 0x6f, 0x67, 0x45, 0x43, 0xda, 0xaa,
		0xe1, 0x3d, 0x39, 0xcf, 0xa9, 0x33, 0x8e, 0x5b, 0xd1, 0xc6, 0x8f, 0xea, 0x79, 0xf5, 0x2b, 0x1c,
		0x4f, 0x6d, 0x38, 0x10, 0x2d, 0x68, 0x31, 0xb8, 0x51, 0xef, 0x38, 0x99, 0xfe, 0xfc, 0xa2, 0x76,
		0xab, 0x14, 0x97, 0xf5, 0x0b, 0xc1, 0x05, 0xca, 0xee, 0xab, 0xc3, 0xe1, 0xc6, 0x3e, 0xa7, 0x8f,
		0x07, 0xc5, 0x7b, 0xa7, 0x79, 0x4f, 0x94, 0xa7, 0x46, 0x4e, 0x4e, 0xba, 0x7e, 0x44, 0x58, 0x51,
		0xe9, 0xfa, 0xe4, 0x23, 0x97, 0x23, 0x51, 0x7e, 0x2c, 0x65, 0x82, 0x8c, 0x51, 0x41, 0xb8, 0xde,
		0x03, 0x11, 0xfb, 0xe9, 0xae, 0x14, 0x27, 0x27, 0x85, 0x02, 0x03, 0x01, 0x00, 0x01,
	}

	config.Intermediate_hops = 3
	config.P2p_hostname = "localhost"
	config.P2p_port = 65504
	config.RpsAddress = "localhost:65530"
	go serveRPS(t)
	initialize()
	time.Sleep(1 * time.Second)
	publicKey, _ := x509.ParsePKCS1PublicKey(destinationPublicKeyRaw)
	tunnelID, err := BuildTunnel(net.IPv4(127, 0, 0, 1), false, 65508, publicKey)
	if err != nil {
		t.Errorf("BuildTunnel error'd out")
		return
	}
	t.Log("TESTING: BUILT TUNNEL WITHOUT ERROR: " + strconv.Itoa(int(tunnelID)))
}