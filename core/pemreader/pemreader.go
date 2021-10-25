package pemreader

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
)

const pemMaxLineLength = 64 + 2

var pemPaddingRegEx = regexp.MustCompile("^-{5}[A-Z0-9 ]*-{5}(\n|\r\n){0,1}$")

type PemReader struct {
	Reader *bufio.Reader
}

func (p *PemReader) Read(byteData []byte) (int, error) {
	if len(byteData) < pemMaxLineLength {
		return 0, errors.New("buffer need to be at least 66 bytes long")
	}
	return p.readNextBase64Line(byteData)
}

func (p *PemReader) readNextBase64Line(byteData []byte) (int, error) {
	readString, err := p.Reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	matchString := pemPaddingRegEx.MatchString(readString)
	if matchString {
		return p.readNextBase64Line(byteData)
	} else {
		if len(readString) > pemMaxLineLength {
			return 0, fmt.Errorf("line was longer than 64 characters %s", matchString)
		} else {
			i := copy(byteData, readString)
			return i, nil
		}
	}
}

func NewPemReader(reader *bufio.Reader) PemReader {
	return PemReader{
		Reader: reader,
	}
}

func IsPemFile(file *os.File) (err error, isPemFile bool) {
	currentPosition, err := file.Seek(0, 1)
	if err != nil {
		return err, false
	}
	defer func() {
		_, errNew := file.Seek(currentPosition, 0)
		if err != nil {
			err = errNew
		}
	}()
	_, err = file.Seek(0, 0)
	if err != nil {
		return err, false
	}
	reader := bufio.NewReader(file)
	line, prefix, err := reader.ReadLine()
	if err != nil {
		return nil, false
	}
	if prefix {
		return nil, false
	}
	lineString := string(line)
	matchString := pemPaddingRegEx.MatchString(lineString)
	return nil, matchString
}
