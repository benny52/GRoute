// Command genicon renders the GRoute sprout shared by the window, executable,
// sidebar and tray. Run go run ./tools/genicon from the repository root.
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
)

type point struct{ x, y float64 }
type polygon []point

func (points polygon) contains(x, y float64) bool {
	inside := false
	last := points[len(points)-1]
	for _, next := range points {
		if (next.y > y) != (last.y > y) && x < next.x+(y-next.y)*(last.x-next.x)/(last.y-next.y) {
			inside = !inside
		}
		last = next
	}
	return inside
}

var (
	outline = polygon{{2, 7}, {8, 10}, {9, 4}, {15, 8}, {22, 3}, {22, 8}, {29, 6}, {27, 22}, {23, 27}, {17, 30}, {10, 28}, {5, 24}}
	face    = polygon{{4, 10}, {10, 13}, {11, 7}, {16, 11}, {20, 7}, {20, 11}, {26, 9}, {24, 22}, {20, 26}, {16, 27}, {9, 25}, {7, 21}}
	bark    = polygon{{5, 11}, {9, 14}, {11, 15}, {11, 22}, {13, 26}, {9, 24}, {7, 21}}
	leaf    = polygon{{17, 10}, {19, 3}, {24, 1}, {29, 1}, {27, 5}, {22, 8}}
	ink     = color.NRGBA{0x3d, 0x2d, 0x24, 0xff}
)

// Draw on a 32-unit grid; leave enough space around the eyes to read at 16 px.
func glyph(x, y float64) color.NRGBA {
	dx, dy := x-16, y-21.5
	angle := math.Atan2(dy, dx) * 180 / math.Pi
	smile := angle >= 25 && angle <= 150 && math.Hypot(dx/4, dy/2.5) <= 1 && math.Hypot(dx/3, dy/1.5) >= 1
	switch {
	case math.Hypot(x-11, y-18) <= 2, math.Hypot(x-21, y-18) <= 2, smile:
		return ink
	case leaf.contains(x, y):
		return color.NRGBA{0x4c, 0x9c, 0x58, 0xff}
	case bark.contains(x, y):
		return color.NRGBA{0xe9, 0xbd, 0x84, 0xff}
	case face.contains(x, y):
		return color.NRGBA{0xc2, 0x8a, 0x54, 0xff}
	case outline.contains(x, y):
		return ink
	default:
		return color.NRGBA{}
	}
}

func render(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const samples = 4
	step := 32.0 / float64(size*samples)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, count int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					c := glyph((float64(x*samples+sx)+0.5)*step, (float64(y*samples+sy)+0.5)*step)
					if c.A != 0 {
						r += int(c.R)
						g += int(c.G)
						b += int(c.B)
						count++
					}
				}
			}
			if count > 0 {
				img.SetNRGBA(x, y, color.NRGBA{uint8(r / count), uint8(g / count), uint8(b / count), uint8(255 * count / (samples * samples))})
			}
		}
	}
	return img
}

func main() {
	out, err := os.Create("build/windows/icon.png")
	if err != nil {
		log.Fatal(err)
	}
	if err := png.Encode(out, render(256)); err != nil {
		log.Fatal(err)
	}
	if err := out.Close(); err != nil {
		log.Fatal(err)
	}
}
