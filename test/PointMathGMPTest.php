<?php
/**
 * Author: oswin
 * Time: 2022/7/1-15:42
 * Description:
 * Version: v1.0
 */

namespace Test;

class PointMathGMPTest extends TestCase
{

    public function testMulPoint(): void
    {
        $kBin = '1100101001011110001111111000010100001000011101111110101000010000011000010011010011100010101000101100100011010111110000000000000110001010100111010100000100101011010110011010101111100110001000111011001011010001101001000011001011110000110100010110001110101000';
        $iMax = strlen($kBin);
        for ($i = 1; $i < $iMax; $i++) {
            var_dump(substr($kBin, $i, 1));
            var_dump($kBin[$i]);
//            var_dump(substr($kBin, $i, 1) == 1);
            break;
        }
    }
}
