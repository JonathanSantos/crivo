// Package slot guarda a política embutida no executável. O slot é uma
// variável de pacote de tamanho fixo; o crivo build acha o slot no arquivo
// do executável e grava a política no lugar (patch in-place), sem anexar
// bytes no fim, o que mantém o executável re-assinável no macOS.
package slot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Layout do slot (64 KiB).
const (
	Size        = 64 << 10
	magicLen    = 16
	stateOffset = 16
	sizeOffset  = 20
	dataOffset  = 24
	// MaxPolicy é o maior texto de política que cabe no slot.
	MaxPolicy = Size - dataOffset

	stateEmpty  = 0
	stateFilled = 1
)

// slot de política; preenchido in-place pelo crivo build
var slot = [Size]byte{'C', 'R', 'I', 'V', 'O', '-', 'S', 'L', 'O', 'T', '-', 'v', '1'}

// Embedded devolve a política embutida, se houver.
func Embedded() ([]byte, bool) {
	return read(slot[:])
}

func read(s []byte) ([]byte, bool) {
	if s[stateOffset] != stateFilled {
		return nil, false
	}
	size := binary.LittleEndian.Uint32(s[sizeOffset:])
	if int(size) > MaxPolicy {
		return nil, false
	}
	return s[dataOffset : dataOffset+int(size)], true
}

// reversedMagic é o marcador invertido. O padrão de busca é montado em
// runtime para não existir uma segunda cópia literal do marcador no binário.
const reversedMagic = "1v-TOLS-OVIRC"

func magic() []byte {
	m := make([]byte, magicLen)
	for i := 0; i < len(reversedMagic); i++ {
		m[i] = reversedMagic[len(reversedMagic)-1-i]
	}
	return m
}

// ErrNoSlot indica que o executável não tem um slot reconhecível.
var ErrNoSlot = errors.New("slot de política não encontrado no executável")

// Find devolve o offset do único slot no conteúdo do executável.
func Find(exe []byte) (int, error) {
	m := magic()
	first := bytes.Index(exe, m)
	if first < 0 {
		return 0, ErrNoSlot
	}
	if bytes.Index(exe[first+1:], m) >= 0 {
		return 0, fmt.Errorf("o marcador do slot aparece mais de uma vez no executável; recuse o build")
	}
	if first+Size > len(exe) {
		return 0, fmt.Errorf("slot truncado no executável")
	}
	return first, nil
}

// Patch grava a política no slot de uma cópia do executável e devolve a cópia.
func Patch(exe, policy []byte) ([]byte, error) {
	if len(policy) > MaxPolicy {
		return nil, fmt.Errorf("a política tem %d bytes; o máximo é %d", len(policy), MaxPolicy)
	}
	off, err := Find(exe)
	if err != nil {
		return nil, err
	}
	s := exe[off : off+Size]
	if s[stateOffset] != stateEmpty {
		return nil, fmt.Errorf("o slot já está preenchido: gere a partir do crivo original, não de um binário gerado")
	}
	for _, b := range s[magicLen:] {
		if b != 0 {
			return nil, fmt.Errorf("o slot não está zerado; executável inesperado")
		}
	}
	out := bytes.Clone(exe)
	ns := out[off : off+Size]
	ns[stateOffset] = stateFilled
	binary.LittleEndian.PutUint32(ns[sizeOffset:], uint32(len(policy)))
	copy(ns[dataOffset:], policy)
	return out, nil
}

// ReadFrom lê a política do slot de um executável em disco (para testes).
func ReadFrom(exe []byte) ([]byte, bool, error) {
	off, err := Find(exe)
	if err != nil {
		return nil, false, err
	}
	p, ok := read(exe[off : off+Size])
	return p, ok, nil
}
