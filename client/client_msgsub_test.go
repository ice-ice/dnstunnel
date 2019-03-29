package client

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"testing"
)

//测试分割回传消息 是否完整
func TestSubMsg(t *testing.T) {
	rootHost := "baidu.com"
	body := "guigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9k"
	shengyuLen := 63 - len(rootHost) - 1 - 1 //减去两个点的长度 和 根域名的长度
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
	b, _ := json.Marshal(msgArray)
	fmt.Println("msgArray len=" + strconv.Itoa(len(msgArray)))
	fmt.Println(string(b))
}
