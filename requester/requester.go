package requester

import (
	"fmt"
	"log"

	"github.com/Martin2877/webloghunter/logparser"
	"github.com/kirinlabs/HttpRequest"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/exp/slices"
)

type Part struct {
	URL       string
	UserAgent string
	Referer   string
}

type Requester struct {
	Address   string `json:"address"`
	Lines     []logparser.Line
	Histories []Part
}

func (ins *Requester) Load(lines []logparser.Line) {
	for _, line := range lines {
		ins.Lines = append(ins.Lines, line)
	}
}

// LoadOne loads a new set of log lines into the requester
// Returns an error if the input lines slice is empty
func (ins *Requester) LoadOne(lines []logparser.Line) error {
	if len(lines) == 0 {
		return fmt.Errorf("no log lines provided")
	}
	ins.Lines = make([]logparser.Line, 0, len(lines))
	ins.Lines = append(ins.Lines, lines...)
	return nil
}

func (ins *Requester) Send() error {
	req := HttpRequest.NewRequest()
	bar := progressbar.Default(int64(len(ins.Lines)))
	for _, line := range ins.Lines {
		part := Part{
			URL:       line.URL,
			UserAgent: line.UserAgent,
			Referer:   line.Referer,
		}
		if slices.Contains(ins.Histories, part) {
			continue
		} else {
			ins.Histories = append(ins.Histories, part)
		}
		bar.Add(1)
		Target := ins.Address + line.URL
		req.SetHeaders(map[string]string{
			"User-Agent": line.UserAgent,
			"Referer":    line.Referer,
		})

		if line.Method == "GET" {
			resp, err := req.Get(Target)
			if err != nil {
				log.Println(err)
				log.Println(err)
				continue
			}
			resp.Close()
			continue
			//time.Sleep(10 * time.Millisecond)
		}
		if line.Method == "POST" {
			resp, err := req.Post(Target, nil)
			if err != nil {
				log.Println(err)
				log.Println(err)
				continue
			}
			resp.Close()
			continue
		}
	}
	return nil
}
