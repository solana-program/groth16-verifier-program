// Generates the gnark Groth16 fixture consumed by program/tests/gnark.rs.
//
// Circuit: three public inputs A, B, C with the constraint A·B = C. The
// witness is fixed (A = 3, B = 5, C = 15) so the fixture is deterministic
// apart from the trusted setup's randomness, which is what makes the proof
// unforgeable and is fine to regenerate.
//
// Outputs, all in gnark's native binary encodings:
//
//	vk.bin         VerifyingKey.WriteTo      (compressed points)
//	vk.raw.bin     VerifyingKey.WriteRawTo   (uncompressed points)
//	proof.bin      Proof.WriteTo             (compressed points)
//	proof.raw.bin  Proof.WriteRawTo          (uncompressed points)
//	public.bin     public Witness.MarshalBinary
//
// Run from this directory: go run .
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type mulCircuit struct {
	A, B, C frontend.Variable `gnark:",public"`
}

func (c *mulCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, new(mulCircuit))
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	assignment := &mulCircuit{A: 3, B: 5, C: 15}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}

	outDir := filepath.Join("..")
	write := func(name string, f func(*bytes.Buffer) error) error {
		var buf bytes.Buffer
		if err := f(&buf); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, buf.Len())
		return nil
	}

	if err := write("vk.bin", func(b *bytes.Buffer) error { _, err := vk.WriteTo(b); return err }); err != nil {
		return err
	}
	if err := write("vk.raw.bin", func(b *bytes.Buffer) error { _, err := vk.WriteRawTo(b); return err }); err != nil {
		return err
	}
	if err := write("proof.bin", func(b *bytes.Buffer) error { _, err := proof.WriteTo(b); return err }); err != nil {
		return err
	}
	if err := write("proof.raw.bin", func(b *bytes.Buffer) error { _, err := proof.WriteRawTo(b); return err }); err != nil {
		return err
	}
	return write("public.bin", func(b *bytes.Buffer) error {
		data, err := publicWitness.MarshalBinary()
		if err != nil {
			return err
		}
		_, err = b.Write(data)
		return err
	})
}
