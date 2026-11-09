package compiler_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// iconPNG is a valid catalog icon of side pixels.
func iconPNG(t *testing.T, side int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, side, side))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (w *world) setIcon(entry uuid.UUID, icon []byte) {
	w.t.Helper()
	w.exec("UPDATE software_catalog_entry SET icon = $2 WHERE id = $1", entry, icon)
}

// object reads an object of the bundles bucket with its content type.
func (w *world) object(key string) ([]byte, string) {
	w.t.Helper()
	out, err := w.s3.Root.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &w.s3.Bucket, Key: &key})
	if err != nil {
		w.t.Fatalf("object %s: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	data, _ := io.ReadAll(out.Body)
	ct := ""
	if out.ContentType != nil {
		ct = *out.ContentType
	}
	return data, ct
}

// TestSoftwareIcons (architect decision A10-14, PDK-935): a package of an entry with a valid icon names the icon's
// digest in the bundle, the icon lies content-addressed below the organization's prefix of the bundles bucket, and the
// bundle pointer maps the entry to it, also after the reconcile loop restored the pointer. A changed icon publishes a
// new bundle; an icon that fails the icon rules is left out.
func TestSoftwareIcons(t *testing.T) {
	w := newWorld(t)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	htop := w.entry("Htop", nil, [4]string{"ubuntu", "*", "*", "htop"})
	vim := w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"})
	w.assign(nano, nil, "available", "latest", nil)
	w.assign(htop, nil, "required", "latest", nil)
	w.assign(vim, nil, "available", "latest", nil)
	icon := iconPNG(t, 32)
	w.setIcon(nano, icon)
	w.setIcon(htop, icon)
	w.setIcon(vim, []byte("GIF89a not a png"))
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)

	sum := hexSHA256(icon)
	key := compiler.IconObjectKey(w.org, sum)
	b := w.fetch(d)
	for _, name := range []string{"nano", "htop"} {
		if p := pkgOf(b.Software, name); p == nil || p.IconSHA256 != sum {
			t.Fatalf("package %s: %+v", name, p)
		}
	}
	if p := pkgOf(b.Software, "vim"); p == nil || p.IconSHA256 != "" {
		t.Fatalf("package with an invalid icon: %+v", p)
	}
	if data, ct := w.object(key); !bytes.Equal(data, icon) || ct != "image/png" {
		t.Fatalf("icon object %q, %d bytes", ct, len(data))
	}
	want := map[string]string{nano.String(): key, htop.String(): key}
	p, _, _ := w.cache.BundlePointer(context.Background(), d)
	if len(p.Icons) != 2 || p.Icons[nano.String()] != key || p.Icons[htop.String()] != key {
		t.Fatalf("pointer icons %+v, want %+v", p.Icons, want)
	}

	// The reconcile loop restores the icons with the pointer from the bundle row.
	if err := w.valkey.Do(context.Background(), w.valkey.B().Del().Key("bp:"+d.String()).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := w.comp.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := w.cache.BundlePointer(context.Background(), d); len(p.Icons) != 2 || p.Icons[nano.String()] != key {
		t.Fatalf("restored pointer icons %+v", p.Icons)
	}

	before := w.version(d)
	changed := iconPNG(t, 48)
	w.setIcon(nano, changed)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) == before {
		t.Fatal("a changed icon did not publish a new bundle")
	}
	newKey := compiler.IconObjectKey(w.org, hexSHA256(changed))
	if p := pkgOf(w.fetch(d).Software, "nano"); p == nil || p.IconSHA256 != hexSHA256(changed) {
		t.Fatalf("package after the icon change: %+v", p)
	}
	if data, _ := w.object(newKey); !bytes.Equal(data, changed) {
		t.Fatal("changed icon not uploaded")
	}
	if p, _, _ := w.cache.BundlePointer(context.Background(), d); p.Icons[nano.String()] != newKey || p.Icons[htop.String()] != key {
		t.Fatalf("pointer icons after the change %+v", p.Icons)
	}
	var row []byte
	if err := w.super.QueryRow(context.Background(), "SELECT icons FROM bundle WHERE device_id = $1 ORDER BY version DESC LIMIT 1",
		d).Scan(&row); err != nil {
		t.Fatal(err)
	}
	var digests map[string]string
	if err := json.Unmarshal(row, &digests); err != nil || digests[nano.String()] != hexSHA256(changed) || len(digests) != 2 {
		t.Fatalf("bundle row icons %s: %v", row, err)
	}
}

// TestSoftwareIconsOlderAgent: an agent before the self-service gate refuses a field it does not know, so its required
// package carries no icon digest, and its pointer names no icon.
func TestSoftwareIconsOlderAgent(t *testing.T) {
	w := newWorld(t)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(nano, nil, "required", "latest", nil)
	w.setIcon(nano, iconPNG(t, 16))
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.agentAt(d, "0.1.0-alpha.9")
	w.mustCompile(statechange.ScopeOrg, w.org)
	b := w.fetch(d)
	if p := pkgOf(b.Software, "nano"); p == nil || p.IconSHA256 != "" {
		t.Fatalf("package %+v", p)
	}
	raw, err := json.Marshal(b.Software)
	if err != nil {
		t.Fatal(err)
	}
	if err := alpha9Accepts(raw); err != nil {
		t.Fatalf("the alpha.9 agent refuses the section: %v", err)
	}
	if p, _, _ := w.cache.BundlePointer(context.Background(), d); p.Icons != nil {
		t.Fatalf("pointer icons %+v", p.Icons)
	}
}

// TestSoftwareIconsUploadedOnce: a content-addressed icon is uploaded once; later bundles that name it, also from a
// restarted compiler, do not upload it again.
func TestSoftwareIconsUploadedOnce(t *testing.T) {
	w := newWorld(t)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(nano, nil, "available", "latest", nil)
	icon := iconPNG(t, 32)
	w.setIcon(nano, icon)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	key := compiler.IconObjectKey(w.org, hexSHA256(icon))
	if n := w.store.putCount(key); n != 1 {
		t.Fatalf("first publish uploaded the icon %d times", n)
	}

	for i, name := range []string{"htop", "vim"} {
		if i == 1 {
			w.restart(func(*compiler.Config) {})
		}
		before := w.version(d)
		e := w.entry(name, nil, [4]string{"ubuntu", "*", "*", name})
		w.assign(e, nil, "available", "latest", nil)
		w.mustCompile(statechange.ScopeOrg, w.org)
		if w.version(d) == before {
			t.Fatalf("adding %s did not publish a new bundle", name)
		}
		if p := pkgOf(w.fetch(d).Software, "nano"); p == nil || p.IconSHA256 != hexSHA256(icon) {
			t.Fatalf("package nano after adding %s: %+v", name, p)
		}
		if n := w.store.putCount(key); n != 1 {
			t.Fatalf("after adding %s the icon was uploaded %d times", name, n)
		}
	}
	if data, _ := w.object(key); !bytes.Equal(data, icon) {
		t.Fatal("icon object lost")
	}
}
