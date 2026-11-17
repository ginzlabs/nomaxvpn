package dataplane

// Device is a TUN the embedder already holds, such as the descriptor a mobile
// OS hands its VPN app. Client configs take one in place of opening a TUN.
type Device interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
	Close() error
	Name() string
}
