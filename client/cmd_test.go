package client

import (
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"testing"
)

func TestCmd(t *testing.T) {
	str := "abcd"
	log.Println(str[1:])

	msgIdStr := "1" + strconv.Itoa(int(123))
	msgId, _ := strconv.Atoi(msgIdStr)
	uint := uint16(msgId)
	log.Println(uint)
	log.Println(exe("whoami"))
}

func exe(commond string) string {
	cmd := exec.Command(commond)
	//创建获取命令输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "Error:can not obtain stdout pipe for command:" + err.Error()
	}
	//执行命令
	if err := cmd.Start(); err != nil {
		return "Error:The command is err," + err.Error()
	}
	//读取所有输出
	bytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "ReadAll Stdout:" + err.Error()
	}
	if err := cmd.Wait(); err != nil {
		return "wait:" + err.Error()
	}
	var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(bytes)
	return string(decodeBytes)
}
