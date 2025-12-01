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
 * Compilation : GOOS=windows GOARCH=amd64 go build  -o dumpdisk_win.exe dumpdisk_win.go
 *
 */

package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	FILE_FLAG_SEQUENTIAL_SCAN        = 0x08000000
	IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procSetFilePointerEx = kernel32.NewProc("SetFilePointerEx")
)

type diskGeometryEx struct {
	Geometry struct {
		Cylinders         int64
		MediaType         uint32
		TracksPerCylinder uint32
		SectorsPerTrack   uint32
		BytesPerSector    uint32
	}
	DiskSize uint64
}

type DiskInfo struct {
	Number int
	Size   uint64
	Path   string
}

func printHelp() {
	fmt.Println("ShadowBytes - DumpDisk")
	fmt.Println("Version 1.0\n")
	fmt.Println("Usage : dumpdisk [-function]\n")
	fmt.Println("Function Available")
	fmt.Println("-if     : Source disk")
	fmt.Println("-of     : target image")
	fmt.Println("-sha256 : Check hash before and after cloning [Optional]")
	fmt.Println("-list   : Show List disk available\n")
	fmt.Println("Ex : dumpdisk.exe -if \\\\.\\PhysicalDrive0 -of Z:\\clone.raw [-sha256]\n")
}

func setFilePointerEx(handle syscall.Handle, offset int64) error {
	var newPos int64
	r1, _, err := procSetFilePointerEx.Call(
		uintptr(handle),
						uintptr(offset),
						uintptr(unsafe.Pointer(&newPos)),
						uintptr(0),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func openDisk(path string) (syscall.Handle, error) {
	return syscall.CreateFile(
		syscall.StringToUTF16Ptr(path),
				  syscall.GENERIC_READ,
			   syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			   nil,
			   syscall.OPEN_EXISTING,
			   FILE_FLAG_SEQUENTIAL_SCAN,
			   0,
	)
}

func getDiskSize(path string) (uint64, uint32, error) {
	handle, err := openDisk(path)
	if err != nil {
		return 0, 0, err
	}
	defer syscall.CloseHandle(handle)

	var bytesReturned uint32
	var geom diskGeometryEx

	err = syscall.DeviceIoControl(
		handle,
		IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geom)),
				      uint32(unsafe.Sizeof(geom)),
				      &bytesReturned,
			       nil,
	)
	if err != nil {
		return 0, 0, err
	}

	sec := geom.Geometry.BytesPerSector
	if sec == 0 {
		sec = 512
	}

	return geom.DiskSize, sec, nil
}

func listDisks() []DiskInfo {
	var disks []DiskInfo
	for i := 0; i < 32; i++ {
		path := fmt.Sprintf(`\\.\PhysicalDrive%d`, i)
		size, _, err := getDiskSize(path)
		if err == nil {
			disks = append(disks, DiskInfo{Number: i, Size: size, Path: path})
		}
	}
	return disks
}

// cloneDisk ne change pas
func cloneDisk(source string, destination string, diskSize int64, sectorSize int64) error {
	handle, err := openDisk(source)

	if err != nil {
		return fmt.Errorf("Unable to open the disc : %v", err)
	}
	defer syscall.CloseHandle(handle)

	out, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("File creation error : %v", err)
	}
	defer out.Close()

	block := make([]byte, 1024*1024)
	var offset int64 = 0

	start := time.Now()
	lastTime := time.Now()
	var bytesSinceLast int64 = 0

	for offset < diskSize {

		if offset%sectorSize != 0 {
			offset = (offset / sectorSize) * sectorSize
		}

		toRead := len(block)
		if int64(toRead) > diskSize-offset {
			toRead = int(diskSize - offset)
		}

		err := setFilePointerEx(handle, offset)
		if err != nil {
			return fmt.Errorf("Error seek : %v", err)
		}

		var bytesRead uint32
		err = syscall.ReadFile(handle, block[:toRead], &bytesRead, nil)
		if err != nil && bytesRead == 0 {
			zero := make([]byte, sectorSize)
			out.Write(zero)
			offset += sectorSize
			fmt.Printf("\rProgress : %.1f%% | Unreadable sector", float64(offset)*100/float64(diskSize))
			continue
		}

		out.Write(block[:bytesRead])
		offset += int64(bytesRead)

		// --- CALCUL DE LA VITESSE ---
		bytesSinceLast += int64(bytesRead)
		elapsed := time.Since(lastTime).Seconds()

		var speedStr string
		if elapsed >= 0.5 {
			speedMB := float64(bytesSinceLast) / (1024 * 1024) / elapsed
			speedStr = fmt.Sprintf("%.1f MB/s", speedMB)
			bytesSinceLast = 0
			lastTime = time.Now()
		} else {
			speedStr = ""
		}

		fmt.Printf("\rProgress : %.1f%% | Speed: %s",
			   float64(offset)*100/float64(diskSize), speedStr)


	}

	fmt.Printf("\nCloning done in %s\n", time.Since(start))
	return nil
}


// calcule le SHA256 d’un fichier ou disque
func computeSHA256(path string, size int64, sectorSize int64) (string, error) {
	handle, err := openDisk(path)
	if err != nil {
		return "", fmt.Errorf("Unable to open %s: %v", path, err)
	}
	defer syscall.CloseHandle(handle)

	h := sha256.New()
	block := make([]byte, 1024*1024)
	var offset int64 = 0

	for offset < size {
		if offset%sectorSize != 0 {
			offset = (offset / sectorSize) * sectorSize
		}

		toRead := len(block)
		if int64(toRead) > size-offset {
			toRead = int(size - offset)
		}

		err := setFilePointerEx(handle, offset)
		if err != nil {
			return "", fmt.Errorf("Error seek : %v", err)
		}

		var bytesRead uint32
		err = syscall.ReadFile(handle, block[:toRead], &bytesRead, nil)
		if err != nil && bytesRead == 0 {
			zero := make([]byte, sectorSize)
			h.Write(zero)
			offset += sectorSize
			continue
		}

		h.Write(block[:bytesRead])
		offset += int64(bytesRead)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// calcule SHA256 pour un fichier normal
func computeSHA256File(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func main() {
	fmt.Println("ShadowBytes - DumpDisk\n")

	now := time.Now() // heure et date actuelles
	// Formater l'heure HH:MM:SS
	hour := now.Format("15:04:05")
	// Formater la date JJ:MM:AAAA
	date := now.Format("02:01:2006")
	fmt.Println("Starting : [" + hour + "] / [" + date +"]")


	ifArg := flag.String("if", "", "Source disk")
	ofArg := flag.String("of", "", "Target raw file")
	listArg := flag.Bool("list", false, "Show available disk")
	shaArg := flag.Bool("sha256", false, "Calculate SHA256 to verify the dump")
	flag.Parse()

	// Liste des disques
	if *listArg {
		disks := listDisks()
		if len(disks) == 0 {
			fmt.Println("No disk detected.")
			return
		}
		fmt.Println("=== Disk Available ===")
		for _, d := range disks {
			fmt.Printf("[%d] %s  -  %.2f Go\n", d.Number, d.Path, float64(d.Size)/(1024*1024*1024))
		}
		return
	}

	// Aucun argument pour clonage -> HELP
	if *ifArg == "" || *ofArg == "" {
		printHelp()
		return
	}

	// Taille du disque
	size, sectorSize, err := getDiskSize(*ifArg)
	if err != nil {
		fmt.Println("Error: Unable to read disk size :", err)
		return
	}

	// Calcul SHA256 avant dump si demandé
	var srcHash string
	if *shaArg {
		fmt.Println("Calculating the SHA256 hash of the source disk...")
		srcHash, err = computeSHA256(*ifArg, int64(size), int64(sectorSize))
		if err != nil {
			fmt.Println("Source SHA256 error :", err)
			return
		}
		fmt.Println("SHA256 source :", srcHash)
	}

	// Clonage
	err = cloneDisk(*ifArg, *ofArg, int64(size), int64(sectorSize))
	if err != nil {
		fmt.Println("Error :", err)
		return
	}

	// Vérification SHA256 du fichier dumpé
	if *shaArg {
		fmt.Println("Calculating the SHA256 hash of the dumped file...")
		dstHash, err := computeSHA256File(*ofArg)
		if err != nil {
			fmt.Println("Error file SHA256 :", err)
			return
		}
		fmt.Println("SHA256 file :", dstHash)

		if srcHash == dstHash {
			fmt.Println("✅ Verification successful: the dump is identical to the source disk")
		} else {
			fmt.Println("❌ Verification failed: the dump differs from the source disk")
		}
	}
}
