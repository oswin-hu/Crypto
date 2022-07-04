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
        $secondSha256 = '1ee2cc1b0x5b3c6c934c15080bb91326e85925f47694a8beec0c23a862cf687fdde6a76a2d440b47d87d049939ef17ecac9d1cd4279bbee0aeabe310db21e033bce81ee2cc1b';
        $key = '0x5b3c6c934c15080bb91326e85925f47694a8beec0c23a862cf687fdde6a76a2d440b47d87d049939ef17ecac9d1cd4279bbee0aeabe310db21e033bce81ee2cc1b';
        $length = strlen($key);
        echo substr($key, $length - 8, 8)."\n";
        var_dump(substr($secondSha256, 0, 8) == substr($key, $length - 8, 8));
        var_dump(strpos($secondSha256, substr($key, $length - 8, 8)) === 0);
    }
}
