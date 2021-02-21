package main

import (
	"log"
	"net/http"

	irisCaptcha "github.com/IrisDev-net/iriscaptchago"
)

const myIrisCaptchaSecret = `533a64afb4c496cc34dfd00d1ecbd45cfa2784b2c3eba4aa02e7a4dcbe081aa40x2711`

func main() {
	ICH, err := irisCaptcha.NewIrisCaptchaHandler(myIrisCaptchaSecret)
	if err != nil {
		log.Panic(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c := r.FormValue("irisCaptcha")
		//! !DOSE NOT RECOMMENDED -  for validation without ip Checking
		// res, err := ICH.Validate(c, "")

		// * Note that is not working on local host, if you want to test it on your localhost use ICH.Validate(c, "") instead.
		res, err := ICH.Validate(c, r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		if !res.Success {
			w.Write([]byte("Wrong Captcha Answer"))
			return
		} else {
			w.Write([]byte("Hooraa Captcha is Solved Correctly"))
			return
		}

	})

	http.ListenAndServe(":8090", nil)
}
