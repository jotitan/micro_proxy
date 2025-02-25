package main

import (
	"bytes"
	"html/template"
)

var htmlTemplate = `
<html>
<head>
<title>Connexion page</title>
<style>
button > a {
	margin:20px;
	padding:10px;
	font-size:24px;
}
div {
	text-align:center;
	margin:10px;
}
body {
	margin-top:100px;
}
</style>
</head>
<body>
<div><button><a href="{{.LinkGuest}}">Connect as guest</a></button></div>
<div><button><a href="{{.LinkSSO}}">Connect as admin</a></button></div>
</body>
</html>
`

type links struct {
	LinkGuest string
	LinkSSO   string
}

func createTemplate(links links) []byte {
	t, _ := template.New("buttons-tmpl").Parse(htmlTemplate)
	buf := bytes.NewBufferString("")
	if t.Execute(buf, links) != nil {
		return []byte{}
	}
	return buf.Bytes()
}
