<?php
/**
 * Author: oswin
 * Time: 2022/7/5-16:39
 * Description:
 * Version: v1.0
 */

namespace Crypto;

use Exception;
use InvalidArgumentException;
use RuntimeException;

class Wallet
{
    private PrivateKey $private_key;
    private string $message_magic;
    private string $network_prefix;
    private string $network_name;

    public function __construct(PrivateKey $private_key, $networkPrefix = '00', $networkName = 'Bitcoin', $messageMagic = null)
    {
        // Private key
        $this->private_key = $private_key;
        // The prefix, network name, and message magic
        $this->setNetworkPrefix($networkPrefix);
        $this->setNetworkName($networkName);
        $this->setMessageMagic($messageMagic);
    }


    /***
     * Set the network prefix, '00' = main network, '6f' = test network.
     *
     * @param  string Hex $prefix
     */
    public function setNetworkPrefix($prefix): void
    {
        // The prefix
        if (!empty($prefix)) {
            $this->network_prefix = $prefix;
        }
    }

    /**
     * Returns the current network prefix, '00' = main network, '6f' = test network.
     *
     * @return string Hex
     */
    public function getNetworkPrefix(): string
    {
        return $this->network_prefix;
    }

    /***
     * Set the network name
     *
     * @param  string  $name
     */
    public function setNetworkName(string $name): void
    {
        // The network name
        if (!empty($name)) {
            $this->network_name = $name;
        }
    }

    /**
     * Returns the current network name
     *
     * @return string
     */
    public function getNetworkName(): string
    {
        return $this->network_name;
    }

    /***
     * Set the magic message prefix
     *
     * @param  string  $magic
     */
    public function setMessageMagic(string $magic): void
    {
        // The signed message "magic" prefix.
        $this->message_magic = $magic;
    }

    /**
     * Returns the current magic message prefix
     *
     * @return string
     */
    public function getMessageMagic(): string
    {
        // Check if a custom messageMagic is being used
        if (!empty($this->message_magic)) {
            // Use the custom one.
            $magic = $this->message_magic;
        } else {
            // Use the default which is: "[LINE_LEN] [NETWORK_NAME] Signed Message:\n"
            $default = $this->getNetworkName()." Signed Message:\n";
            $magic   = $this->numToVarIntString(strlen($default)).$default;
        }
        return $magic;
    }

    /**
     * @return PrivateKey
     * @throws Exception
     */
    private function getPrivateKey(): ?PrivateKey
    {
        if (!empty($this->private_key)) {
            throw new RuntimeException('Wallet does not have a private key');
        }

        return $this->private_key;
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @return String Base58
     * @throws Exception
     */
    public function getAddress(): string
    {
        $address    = '';
        $privateKey = $this->getPrivateKey();
        if ($privateKey instanceof PrivateKey) {
            $pubKeyPoints = $privateKey->getPubKeyPoints();
            $DERPubkey    = AddressCodec::compress($pubKeyPoints);
            $address      = AddressCodec::encode(AddressCodec::hash($DERPubkey), $this->getNetworkPrefix());
        }
        return $address;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function getUncompressedAddress(): string
    {
        $address    = '';
        $privateKey = $this->getPrivateKey();
        if ($privateKey instanceof PrivateKey) {
            $pubKeyPoints = $privateKey->getPubKeyPoints();
            $address      = AddressCodec::hex(AddressCodec::hash($pubKeyPoints));
        }

        return $address;
    }


    /***
     * Satoshi client's standard message signature implementation.
     *
     * @param $message
     * @param  bool  $compressed
     * @param  null  $nonce
     * @return string
     * @throws Exception
     */
    public function signMessage($message, bool $compressed = true, $nonce = null): string
    {

        $hash   = $this->hash256($this->getMessageMagic().$this->numToVarIntString(strlen($message)).$message);
        $points = Signature::getSignatureHashPoints(
            $hash,
            $this->getPrivateKey()->getPrivateKey(),
            $nonce
        );

        $R = $points['R'];
        $S = $points['S'];

        while (strlen($R) < 64) {
            $R = '0'.$R;
        }

        while (strlen($S) < 64) {
            $S = '0'.$S;
        }

        $res = "\n-----BEGIN ".strtoupper($this->getNetworkName())." SIGNED MESSAGE-----\n";
        $res .= $message;
        $res .= "\n-----BEGIN SIGNATURE-----\n";
        if (true === $compressed) {
            $res .= $this->getAddress()."\n";
        } else {
            $res .= $this->getUncompressedAddress()."\n";
        }

        $finalFlag = 0;
        for ($i = 0; $i < 4; $i++) {
            $flag = 27;
            if (true === $compressed) {
                $flag += 4;
            }
            $flag += $i;

            $pubKeyPts = $this->getPrivateKey()->getPubKeyPoints();
            //echo "\nReal pubKey : \n";
            //print_r($pubKeyPts);

            $recoveredPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
            //echo "\nRecovered PubKey : \n";
            //print_r($recoveredPubKey);

            if (AddressCodec::Compress($pubKeyPts) === $recoveredPubKey) {
                $finalFlag = $flag;
            }
        }

        //echo "Final flag : " . dechex($finalFlag) . "\n";
        if (0 === $finalFlag) {
            throw new RuntimeException('Unable to get a valid signature flag.');
        }


        $res .= base64_encode(hex2bin(dechex($finalFlag).$R.$S));
        $res .= "\n-----END ".strtoupper($this->getNetworkName())." SIGNED MESSAGE-----";

        return $res;
    }


    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $rawMessage
     * @return bool
     * @throws Exception
     */
    public function checkSignatureForRawMessage($rawMessage): ?bool
    {
        //recover message.
        preg_match_all("#-----BEGIN " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----#USi", $rawMessage, $out);
        $address = $out[1][0];
        $signature = $out[2][0];

        // Alternate version
        //return $this->checkSignedMessage($address, $signature, $message);
        return $this->checkSignatureForMessage($address, $signature, $message);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $address String
     * @param $encodedSignature String
     * @param $message String
     * @return bool
     * @throws Exception
     */
    public function checkSignatureForMessage(string $address, string $encodedSignature, string $message): ?bool
    {
        // $hash is HEX String
        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

        //recover flag

        // $signature is BIN
        $signature = base64_decode($encodedSignature);

        // $flag is INT
        $flag = hexdec(bin2hex($signature[0]));

        // Convert BIN to HEX String
        $R = bin2hex(substr($signature, 1, 32));
        $S = bin2hex(substr($signature, 33));

        $derPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($derPubKey), $this->getNetworkPrefix());

        /* Alternate version
        $pubkeyPoint = Signature::recoverPublicKey_HEX($flag, $R, $S, $hash);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash(AddressCodec::Compress($pubkeyPoint)), $this->getNetworkPrefix());
        */
        return $address === $recoveredAddress;
    }


    /**
     * Same as above - But not working correctly
     * All Paramaters are Strings
     *
     * @param $address
     * @param $encodedSignature
     * @param $message
     * @return bool
     * @throws Exception
     */
    public function checkSignedMessage($address, $encodedSignature, $message): bool
    {
        // $signature is BIN
        $signature = base64_decode($encodedSignature, true);

        // $recoveryFlags is INT
        $recoveryFlags = ord($signature[0]) - 27;

        if ($recoveryFlags < 0 || $recoveryFlags > 7) {
            throw new InvalidArgumentException('invalid signature type');
        }

        // $isCompressed is BOOL
        $isCompressed = ($recoveryFlags & 4) !== 0;

        // $hash is HEX String
        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

        // Convert BIN to HEX String
        $R = gmp_init(bin2hex(substr($signature, 1, 32)), 16);
        $S = gmp_init(bin2hex(substr($signature, 33)), 16);

        $hash = gmp_init($hash, 16);

        // $pubkey is Array(HEX String, HEX String)
        $pubkeyPoint = Signature::recoverPublicKey($R, $S, $hash, $recoveryFlags);

        if ($isCompressed) {
            $recoveredAddress = AddressCodec::Compress($pubkeyPoint);
        }
        else{
            $recoveredAddress = AddressCodec::Hex($pubkeyPoint);
        }

        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($recoveredAddress), $this->getNetworkPrefix());
        return $address === $recoveredAddress;
    }

    /***
     * Standard 256 bit hash function : double sha256
     *
     * @param $data
     * @return string
     */
    private function hash256($data): string
    {
        return hash('sha256', hex2bin(hash('sha256', $data)));
    }

    /***
     * Convert a number to a compact Int
     * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
     *
     * @param $i
     * @return string
     * @throws Exception
     */
    private function numToVarIntString($i): ?string
    {
        if ($i < 0xfd) {
            return chr($i);
        }

        if ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        }

        if ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        }

        throw new RuntimeException('int too large');
    }

}
