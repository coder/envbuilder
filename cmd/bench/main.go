package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/image/remote"
	"github.com/GoogleContainerTools/kaniko/pkg/util"

	"github.com/coder/envbuilder/benchmark"
)

func main() {
	if true {
		img, err := benchmark.Image(context.Background(), "testing", "/home/kyle/projects/coder/envbuilder/benchmark/.cache")
		if err != nil {
			panic(err)
		}
		fmt.Printf("Tar %s\n", tar)

		err = benchmark.Registry(tar)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Got image %s\n", tar)
		return
	}

	if len(os.Args) < 3 {
		panic("Must provide image name and target")
	}
	dir := os.Args[1]
	imgRef := os.Args[2]

	start := time.Now()
	err := run(dir, imgRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("run: %s\n", time.Since(start))
}

func run(dir, imgRef string) error {
	img, err := remote.RetrieveRemoteImage(imgRef, config.RegistryOptions{}, "linux/amd64")
	if err != nil {
		return fmt.Errorf("get remote image: %w", err)
	}

	if false {
		_, err = util.GetFSFromImage(dir, img, util.ExtractFile)
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("get layers: %w", err)
	}
	for index, layer := range layers {
		// media, err := layer.MediaType()
		// if err != nil {
		// 	return fmt.Errorf("get media type: %w", err)
		// }
		compressed, err := layer.Compressed()
		if err != nil {
			return fmt.Errorf("get compressed: %w", err)
		}
		defer compressed.Close()

		file, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("layer-%d.tar.gz", index)), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("open file: %w", err)
		}
		defer file.Close()
		_, err = io.Copy(file, compressed)
		if err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		continue

		rdr, err := gzip.NewReader(compressed)
		if err != nil {
			return fmt.Errorf("new reader: %w", err)
		}
		defer rdr.Close()
		err = untar(rdr, dir)
		if err != nil {
			return fmt.Errorf("untar: %w", err)
		}

		// tr := tar.NewReader(rdr)
		// for {
		// 	hdr, err := tr.Next()
		// 	if errors.Is(err, io.EOF) {
		// 		break
		// 	}
		// 	if err != nil {
		// 		return fmt.Errorf("next: %w", err)
		// 	}
		// 	err = util.ExtractFile(dir, hdr, tr)
		// 	if err != nil {
		// 		return fmt.Errorf("extract file: %w", err)
		// 	}
		// }
	}
	return err
}

const MemorySliceSize = 10 * 1024 * 1024
const NumMemorySlices = 50

type BufferAndSlice struct {
	Buffer    *[MemorySliceSize]byte
	N         int64
	NeedsMore bool
}

type SymlinkToMake struct {
	Src  string
	Dest string
}

func untar(r io.Reader, dir string) (err error) {
	madeDir := &map[string]bool{}
	madeDirMutex := sync.Mutex{}
	madeDirPtr := (*unsafe.Pointer)(unsafe.Pointer(&madeDir))

	t0 := time.Now()
	var nFiles int64
	mkdirMaybe := func(dir string) error {
		madeDir := (*map[string]bool)(atomic.LoadPointer(madeDirPtr))

		if !(*madeDir)[dir] {
			fmt.Printf("Mkdir %s\n", dir)
			if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
				fmt.Printf("Mkdir error %s\n", err)
				return err
			}

			madeDirMutex.Lock()
			madeDir = (*map[string]bool)(atomic.LoadPointer(madeDirPtr))
			newDir := make(map[string]bool, len(*madeDir))
			for k, v := range *madeDir {
				newDir[k] = v
			}
			newDir[dir] = true
			atomic.StorePointer(madeDirPtr, unsafe.Pointer(&newDir))
			madeDirMutex.Unlock()
		}
		return nil
	}
	defer func() {
		td := time.Since(t0)
		if err == nil {
			log.Printf("extracted tarball into %s: %d files, %d dirs (%v)", dir, nFiles, len(*madeDir), td)
		} else {
			log.Printf("error extracting tarball into %s after %d files, %d dirs, %v: %v", dir, nFiles, len(*madeDir), td, err)
		}
	}()

	recycler := make(chan *[MemorySliceSize]byte, NumMemorySlices)
	for i := 0; i < NumMemorySlices; i += 1 {
		recycler <- &[MemorySliceSize]byte{}
	}
	var wg sync.WaitGroup
	// A ghetto way to wait for all goroutines to terminate.
	defer func() {
		wg.Wait()
	}()
	errchan := make(chan error, 1)
	minCap := len(recycler)
	numOverflows := 0
	defer func() {
		log.Printf("Lowest queue size %v; overflows %v", minCap, numOverflows)
	}()

	tr := tar.NewReader(r)
	loggedChtimesError := false
	for {
		select {
		case err := <-errchan:
			return err
		default:
		}

		f, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("tar reading error: %v", err)
			return fmt.Errorf("tar error: %v", err)
		}
		if !validRelPath(f.Name) {
			// return fmt.Errorf("tar contained invalid name error %q", f.Name)
		}
		rel := filepath.FromSlash(f.Name)
		abs := filepath.Join(dir, rel)

		fi := f.FileInfo()
		mode := fi.Mode()
		switch {
		case mode.IsRegular():
			chunkChan := make(chan BufferAndSlice, 1)
			completion := make(chan struct{}, 1)
			wg.Add(1)
			go func() {
				// Make the directory. This is redundant because it should
				// already be made by a directory entry in the tar
				// beforehand. Thus, don't check for errors; the next
				// write will fail with the same error.
				dir := filepath.Dir(abs)
				err := mkdirMaybe(dir)
				if err != nil {
					firstChunk := <-chunkChan
					recycler <- firstChunk.Buffer
					completion <- struct{}{}
					wg.Done()
					return
				}

				wf, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode.Perm())
				if err != nil && os.IsPermission(err.(*os.PathError).Unwrap()) {
					os.Remove(abs)
					wf, err = os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
				}
				fmt.Printf("err %v\n", err)
				firstChunk := <-chunkChan
				defer func() {
					recycler <- firstChunk.Buffer
					wg.Done()
				}()

				if err != nil {
					select {
					case errchan <- err:
					default:
					}
					completion <- struct{}{}
					return
				}

				var n int64
				n1, err := wf.Write((*firstChunk.Buffer)[:firstChunk.N])
				n += int64(n1)
				if firstChunk.NeedsMore && err == nil {
					n2, err2 := io.Copy(wf, tr)
					err = err2
					n += n2
					completion <- struct{}{}
				}
				if closeErr := wf.Close(); closeErr != nil && err == nil {
					err = closeErr
				}
				if err != nil {
					select {
					case errchan <- fmt.Errorf("error writing to %s: %v", abs, err):
					default:
					}
					return
				}
				if n != f.Size {
					select {
					case errchan <- fmt.Errorf("only wrote %d bytes to %s; expected %d", n, abs, f.Size):
					default:
					}
					return
				}
				modTime := f.ModTime
				if modTime.After(t0) {
					// Clamp modtimes at system time. See
					// golang.org/issue/19062 when clock on
					// buildlet was behind the gitmirror server
					// doing the git-archive.
					modTime = t0
				}
				if !modTime.IsZero() {
					if err := os.Chtimes(abs, modTime, modTime); err != nil && !loggedChtimesError {
						// benign error. Gerrit doesn't even set the
						// modtime in these, and we don't end up relying
						// on it anywhere (the gomote push command relies
						// on digests only), so this is a little pointless
						// for now.
						log.Printf("error changing modtime: %v (further Chtimes errors suppressed)", err)
						loggedChtimesError = true // once is enough
					}
				}
				atomic.AddInt64(&nFiles, 1)
			}()
			lr := len(recycler)
			if lr < minCap {
				minCap = lr
			}

			buffer := <-recycler
			n, err := io.ReadFull(tr, (*buffer)[:])
			if err == io.ErrUnexpectedEOF {
				// Not real - we are going async!
				chunkChan <- BufferAndSlice{Buffer: buffer, N: int64(n), NeedsMore: false}
			} else {
				numOverflows++
				chunkChan <- BufferAndSlice{Buffer: buffer, N: int64(n), NeedsMore: true}
				<-completion
			}

		case mode.IsDir():
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := mkdirMaybe(abs)
				if err != nil {
					select {
					case errchan <- err:
					default:
					}
				}
			}()
		case mode&os.ModeSymlink != 0:
			wg.Add(1)
			go func() {
				defer wg.Done()
				dir := filepath.Dir(abs)
				err := mkdirMaybe(dir)
				if err == nil {
					err = os.Symlink(f.Linkname, abs)
					if os.IsExist(err) {
						os.Remove(abs)
						err = os.Symlink(f.Linkname, abs)
					}
				}
				if err != nil {
					select {
					case errchan <- err:
					default:
					}
					return
				}
				atomic.AddInt64(&nFiles, 1)
			}()
		default:
			return fmt.Errorf("tar file entry %s contained unsupported file type %v", f.Name, mode)
		}
	}
	wg.Wait()
	select {
	case err = <-errchan:
	default:
	}
	if err != nil {
		return err
	}
	return nil
}

func validRelativeDir(dir string) bool {
	if strings.Contains(dir, `\`) || path.IsAbs(dir) {
		return false
	}
	dir = path.Clean(dir)
	if strings.HasPrefix(dir, "../") || strings.HasSuffix(dir, "/..") || dir == ".." {
		return false
	}
	return true
}

func validRelPath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}
