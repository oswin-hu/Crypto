<?php
/**
 * Author: oswin
 * Time: 2022/7/5-16:11
 * Description:
 * Version: v1.0
 */

namespace Test;

use Crypto\AddressCodec;

class AddressCodecTest extends TestCase
{

    public function testPoint(): void
    {
        $x = 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
        $y = '5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235';
        $derPublicKey = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235';
        $point = AddressCodec::point($derPublicKey);
        $rtn = false;
        if ($x === $point['x'] && $y === $point['y']){
            $rtn = true;
        }
        $this->assertTrue($rtn);
    }

    public function testDecompress(): void
    {

        $addressStr = '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV';
        $addressPex = 'ZS67wSwchNQFuTt3abnK4HjpjQ2x79YZed';
        $compressedPublicKey = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
        $point = AddressCodec::decompress($compressedPublicKey);
        echo $point['x']."\n";
        echo $point['y']."\n";
        $compressedPublicKey = AddressCodec::compress($point);
        $derPublicKey = AddressCodec::hex($point);
        $hash = AddressCodec::hash($compressedPublicKey);
        $address = AddressCodec::encode($hash);
        echo $address."\n";

        $rtn = false;
        if ($addressStr === $address){
            $rtn = true;
        }
        $this->assertTrue($rtn);
    }
}
