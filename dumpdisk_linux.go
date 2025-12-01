/*
 * DumpDisk for GNU/Linux
 * Create by : X-n0
 * Date : 25/11/2025
 * License : GPL V3
 *
 * DumpDisk allows you to create a complete image of a storage device for forensic analysis.
 * The advantage is that the tool can copy a disk (bit by bit) to an image but not the other way around,
 * which helps protect the system and prevents overwriting the source disk.
 *
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Couleurs pour l'affichage
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBlue   = "\033[34m"
)

// Parse la taille du bloc depuis une string type "10M" ou "4K"
func parseBlockSize(bs string) (int, error) {
	bs = strings.ToUpper(bs)
	multiplier := 1
	if strings.HasSuffix(bs, "K") {
		multiplier = 1024
		bs = strings.TrimSuffix(bs, "K")
	} else if strings.HasSuffix(bs, "M") {
		multiplier = 1024 * 1024
		bs = strings.TrimSuffix(bs, "M")
	} else if strings.HasSuffix(bs, "G") {
		multiplier = 1024 * 1024 * 1024
		bs = strings.TrimSuffix(bs, "G")
	}
	val, err := strconv.Atoi(bs)
	if err != nil {
		return 0, err
	}
	return val * multiplier, nil
}

// Calcul SHA-256 d'un fichier dump
func computeSHA256(path string, blockSize int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash := sha256.New()
	buf := make([]byte, blockSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			hash.Write(buf[:n]) 
		}
		if err != nil {
			if err == io.EOF {
				break 
			}
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func cloneDisk(srcPath, dstPath string, blockSize int) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("Open source error : %v", err)
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("Destination creation error : %v", err)
	}
	defer out.Close()

	buf := make([]byte, blockSize)
	var totalCopied int64 = 0     
	start := time.Now()           

	for {
		n, err := in.Read(buf)
		if n > 0 {
			written, err2 := out.Write(buf[:n])
			if err2 != nil {
				return fmt.Errorf("Error writing : %v", err2)
			}
			totalCopied += int64(written)
			// Calcul vitesse et affichage
			elapsed := time.Since(start).Seconds()
			speed := float64(totalCopied) / (1024 * 1024) / elapsed
			fmt.Printf("\r%sTotal copied : %d MB | Speed : %.2f MB/s%s",
				ColorCyan, totalCopied/(1024*1024), speed, ColorReset)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("Error read : %v", err)
		}
	}
	fmt.Println("\n" + ColorGreen + "Cloning Done." + ColorReset)
	return nil
}

func main() {
	fmt.Println("ShadowBytes - DumpDisk\n")
    now := time.Now() 
	hour := now.Format("15:04:05")
	date := now.Format("02:01:2006")
    fmt.Println(ColorYellow + "Starting : [" + hour + "] / [" + date +"]" + ColorReset)
	src := flag.String("if", "", "Source Disk (ex: /dev/sdb)")
	dst := flag.String("of", "", "Target Disk (ex: dump.img)")
	noHash := flag.Bool("nohash", false, "Disable calcul hash [SHA-256]")
	bsFlag := flag.String("bs", "4M", "Bloc Size (ex: 4M, 10M, 512K)")
	flag.Parse()
	// Vérification des arguments
	if *src == "" || *dst == "" {
        fmt.Println("ShadowBytes - DumpDisk")
		fmt.Println("Version 1.0\n")
		fmt.Println("Usage : dumpdisk [--function]\n")
		fmt.Println("Function Available :")
		fmt.Println("-if     : Source disk")
		fmt.Println("-of     : Target disk")
		fmt.Println("-nohash : No check hash (sha256) [Optional]")
		fmt.Println("-bs     : Size Block [Optional]\n")
		fmt.Println("Ex : dumpdisk -if /dev/sda -of copydisk.img -nohash -bs 10M\n")
		return
	}
	blockSize, err := parseBlockSize(*bsFlag)
	if err != nil || blockSize <= 0 {
		fmt.Println(ColorRed+"Error : invalid block size"+ColorReset, err)
		return
	}
	doHash := !*noHash
	if doHash {
		fmt.Println(ColorYellow + "SHA-256 mode enabled" + ColorReset)
	} else {
		fmt.Println(ColorYellow + "Hashless mode (-nohash)" + ColorReset)
	}
	var hashBefore, hashAfter string
	// Hash avant clonage
	if doHash {
		fmt.Println(ColorBlue + "SHA-256 calculation of the source disk..." + ColorReset)
		hashBefore, err = computeSHA256(*src, blockSize)
		if err != nil {
			fmt.Println(ColorRed+"Error :", err, ColorReset)
			return
		}
		fmt.Println(ColorGreen+"Source SHA-256 :", hashBefore, ColorReset)
	}
	// Clonage
	fmt.Println("Cloning in progress...")
	if err := cloneDisk(*src, *dst, blockSize); err != nil {
		fmt.Println(ColorRed+"Error cloning :", err, ColorReset)
		return
	}
	// Hash après clonage
	if doHash {
		fmt.Println("SHA-256 calculation of the cloned file...")
		hashAfter, err = computeSHA256(*dst, blockSize)
		if err != nil {
			fmt.Println(ColorRed+"Error :", err, ColorReset)
			return
		}
		fmt.Println(ColorGreen+"SHA-256 dump :", hashAfter, ColorReset)
		// Vérification hash
		if hashBefore == hashAfter {
			fmt.Println(ColorGreen + "✔ Verification OK : the dump is identical" + ColorReset)
		} else {
			fmt.Println(ColorRed + "❌ Failure: the hashes do not match" + ColorReset)
		}
	} else {
		fmt.Println(ColorYellow + "No hash requested. Operation complete." + ColorReset)
	}
}
