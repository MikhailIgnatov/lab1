package main

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"pkcs7"
	"strings"
	"time"
)

type mFile struct {
	Name   string    `xml:"name"`
	Size   int64     `xml:"size"`
	CSize  int64     `xml:"compressed_size"`
	Modify time.Time `xml:"modify"`
	Hash   string    `xml:"hash"`
}
type meta struct {
	File []mFile `xml:"file"`
}

var Path string
var Output string
var Mode string
var List []mFile
var Hash string
var CertificateName string
var KeyName string

func init() {
	flag.StringVar(&Path, "path", "./", "Here you should place Path")
	flag.StringVar(&Output, "out", "out.zip", "Here you should place Name of your zip")
	flag.StringVar(&Mode, "mode", "", "Here you should place z - to zip, sz - to sertificate zip, u - to unzip")
	flag.StringVar(&Hash, "hash", "", "Here you should place hash")
	flag.StringVar(&CertificateName, "cert", "./", "Here you should place path to certificate")
	flag.StringVar(&KeyName, "pkey", "./", "Here you should place path to private key")
}

func main() {
	flag.Parse()

	switch Mode {
	case "z":

		newZipFile := new(bytes.Buffer)
		ZipWriter := zip.NewWriter(newZipFile) //создается записыватель в zip

		err := ZipFiles(Path, ZipWriter, "")
		if err != nil {
			log.Printf(err.Error())
			return
		}
		err = ZipWriter.Close()
		if err != nil {
			log.Printf(err.Error())
			return
		}
		fmt.Println("Files were zipped")

		for i, file := range List {
			err := List[i].fixName(Path)
			if err != nil {
				log.Printf(err.Error())
				return
			} else {
				fmt.Println(file.Name)
			}
		}

		ZipMetaFile, err := CreateMeta(List, newZipFile)
		if err != nil {
			log.Printf(err.Error())
			return
		}

		EndZip := new(bytes.Buffer)
		biteSize := make([]byte, 4)
		binary.LittleEndian.PutUint32(biteSize, uint32(ZipMetaFile.Len()))

		_, err = EndZip.Write(biteSize)
		if err != nil {
			log.Printf(err.Error())
			return
		}

		_, err = EndZip.Write(ZipMetaFile.Bytes())
		if err != nil {
			log.Printf(err.Error())
			return
		}

		_, err = EndZip.Write(newZipFile.Bytes())
		if err != nil {
			log.Printf(err.Error())
			return
		}

		err = SignZip(CertificateName, KeyName, Output, EndZip)
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "x":
		err := Extract()
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "i":
		sign, err := Verify()
		if err != nil {
			log.Printf(err.Error())
			return
		} else {
			fmt.Println("Sign is verified")
		}
		if Hash != "" {
			signer := sign.GetOnlySigner()
			if Hash == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {
				fmt.Println("Hashes are equal!")
			} else {
				fmt.Println("Hashes are not equal! Sing is broken")
			}
		}
		data := sign.Content

		buf, mlen, err := ReadMeta(data)
		if err != nil {
			log.Printf(err.Error())
			return
		}

		mlen = mlen
		fmt.Printf(string(buf.Bytes()))

	default:
		log.Printf("Unknown key for mode")
		return

	}

}

func ZipFiles(path string, zipWriter *zip.Writer, dirName string) error {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			_, err := zipWriter.Create(filepath.Join(dirName, file.Name()) + "/")
			if err != nil {
				return err
			}

			err = ZipFiles(filepath.Join(path, file.Name()), zipWriter, filepath.Join(dirName, file.Name()))
			if err != nil {
				return err
			}
		} else {
			L := new(mFile)
			data, err := os.Open(filepath.Join(path, file.Name()))
			defer data.Close()
			if err != nil {
				return err
			}

			info, err := data.Stat()
			if err != nil {
				return err
			}

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}

			header.Name = filepath.Join(dirName, file.Name())

			header.Method = zip.Deflate

			zwriter, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}

			if _, err = io.Copy(zwriter, data); err != nil {
				return err
			}

			L.Name = filepath.Join(path, file.Name())
			L.Size = file.Size()
			L.CSize = int64(header.CompressedSize64)
			L.Modify = header.Modified
			h := sha1.New()
			d, err := ioutil.ReadFile(L.Name)
			if err != nil {
				return err
			}
			_, err = h.Write(d)
			if err != nil {
				return err
			}

			L.Hash = base64.URLEncoding.EncodeToString(h.Sum(nil))
			List = append(List, *L)

		}
	}
	return nil
}

func (f *mFile) fixName(path string) error {
	var err error
	f.Name, err = filepath.Rel(path, f.Name)
	return err
}

func CreateMeta(list []mFile, zipFile *bytes.Buffer) (*bytes.Buffer, error) {

	var l meta
	l.File = list
	output, err := xml.MarshalIndent(l, "  ", "    ")
	if err != nil {
		log.Printf("error: %v\n", err)
		return nil, err
	}

	MetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(MetaBuf)

	m, err := zipMetaWriter.Create("meta.xml")
	if err != nil {
		return nil, err
	}

	_, err = m.Write(output)
	if err != nil {
		return nil, err
	}

	err = zipMetaWriter.Close()
	if err != nil {
		return nil, err
	}

	return MetaBuf, nil
}

func SignZip(cert string, key string, Output string, zipFile *bytes.Buffer) error {

	signedData, err := pkcs7.NewSignedData(zipFile.Bytes())
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
		return err
	}

	certificateFile, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Printf("failed to read certificate")
		return errors.New("failed to parse certificate from file")
	}

	certificateBlock, _ := pem.Decode(certificateFile)
	if certificateBlock == nil {
		log.Printf("failed to parse certificate PEM")
		return errors.New("failed to parse certificate PEM")
	}

	recpcert, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		log.Printf("failed to parse certificate: " + err.Error())
		return err
	}

	pkeyFile, err := ioutil.ReadFile(key)
	if err != nil {
		log.Printf("Can not read private key file")
		return err
	}

	block, _ := pem.Decode(pkeyFile)
	if block == nil {
		log.Printf("failed to parse private key PEM")
		return errors.New("failed to parse private key PEM")
	}

	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	var recpkey *rsa.PrivateKey
	recpkey = parseResult.(*rsa.PrivateKey)

	signedData.AddSigner(recpcert, recpkey, pkcs7.SignerInfoConfig{})
	if err != nil {
		log.Printf("error")
		return err
	}

	detachedSignature, err := signedData.Finish()
	if err != nil {
		log.Printf("error")
		return err
	}

	sz, err := os.Create(Output)
	defer sz.Close()
	if err != nil {
		log.Printf("error")
		return err
	}

	fmt.Println("Hash of certificate: " + strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(recpcert.Raw))))

	_, err = sz.Write(detachedSignature)
	if err != nil {
		log.Printf("error")
		return err
	}

	fmt.Println("Data signed")
	return nil
}

func Extract() error {
	sign, err := Verify()
	if err != nil {
		log.Printf("Sign was not found")
		return err
	}

	fmt.Println("Sign was verified")
	data, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("unable to read szp")
		return err
	}

	signer := sign.GetOnlySigner()
	if Hash != "" {
		if Hash == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {
			fmt.Println("Hashes are equal!")
		} else {
			fmt.Println("Hashes are not equal! Sing is broken")
		}
	} else {
		fmt.Println("Hash of sign: " + strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))))
	}

	data = sign.Content
	buf, mlen, err := ReadMeta(data)
	if err != nil {
		log.Printf(err.Error())
		return err
	}

	dzip := data[mlen+4:] // считываю остальную часть архива с файлами
	xmlMeta := new(meta)

	err = xml.Unmarshal(buf.Bytes(), xmlMeta)
	if err != nil {
		log.Printf(err.Error())
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(dzip), int64(len(dzip)))
	if err != nil {
		log.Printf("Can not open zip")
		return err
	}

	var fm os.FileMode
	err = os.RemoveAll("extract")
	if err != nil {
		log.Printf("dir extract was made")
	}
	err = os.Mkdir("extract", fm) //создаю папку для извлечения
	if err != nil {
		log.Printf("can not create dir")
		return err
	}
	p := "./extract"
	i := 0 //счетчик для метаданных
	for _, f := range r.File {
		dirs, _ := filepath.Split(f.Name)

		if f.ExternalAttrs == 0 { //Если папка, то равно 0, если файл, то не равно 0

			err = os.Mkdir(filepath.Join(p, dirs), fm)

			if err != nil {
				log.Printf(err.Error())
			}

		} else {

			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				log.Printf(err.Error())
			}

			file, err := os.Create(filepath.Join(p, f.Name))
			defer file.Close()
			if err != nil {
				log.Printf(err.Error())
			}

			_, err = io.Copy(file, rc)
			if err != nil {
				log.Printf(err.Error())
			}

			//вычисляю хэш
			h := sha1.New()
			fileHash, err := ioutil.ReadFile(filepath.Join(p, f.Name))
			_, err = h.Write(fileHash)
			if err != nil {
				log.Printf(err.Error())
			}
			hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

			if hash == xmlMeta.File[i].Hash {
				fmt.Printf(f.Name + " hashes are equal\n")
			} else {
				fmt.Printf(f.Name + " hash is broken!\n")
			}

			i++
		}
	}
	return nil
}

func ReadMeta(data []byte) (*bytes.Buffer, uint32, error) {
	mlen := binary.LittleEndian.Uint32(data[:4]) //получаю длину метаданных
	bmeta := data[4 : mlen+4]                    //получаю байты метаданных

	m, err := zip.NewReader(bytes.NewReader(bmeta), int64(len(bmeta)))
	if err != nil {
		log.Printf("Can not open meta")
		return nil, mlen, err
	}

	f := m.File[0] //т.к. в архиве меты всего 1 файл, получаю его
	buf := new(bytes.Buffer)

	st, err := f.Open()
	if err != nil {
		log.Printf(err.Error())
		return nil, mlen, err
	}
	_, err = io.Copy(buf, st)
	if err != nil {
		log.Printf(err.Error())
		return nil, mlen, err
	}
	return buf, mlen, nil
}

func Verify() (sign *pkcs7.PKCS7, err error) {
	szip, err := ioutil.ReadFile(Output)
	if err != nil {
		log.Printf("Unable to read zip")
		return nil, err
	}
	sign, err = pkcs7.Parse(szip)
	if err != nil {
		log.Printf("Sign is broken!")
		return sign, err
	}
	err = sign.Verify()
	if err != nil {
		log.Printf("Sign is not verified")
		return sign, err
	}
	return sign, nil
}
