package aes

import (
	"fmt"
	"testing"
)

func TestAes(t *testing.T) {
	//务必16位
	AesKey = "321423u9y8d2fwfl"
	enStr, err := AesEncrypt([]byte("guigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9kguigjdfsjkl;ewlrejltejggfklldldlfkjksjskadsjtjgjvgldlkaskjdkiksdkjgju2u3i39g9gijkekeklfjbhsjiqi9193o9k"), []byte(AesKey))
	fmt.Println(err)
	fmt.Println(enStr)

	deStr, err := AesDecrypt(enStr, []byte(AesKey))
	fmt.Println(err)
	fmt.Println(string(deStr))
}
