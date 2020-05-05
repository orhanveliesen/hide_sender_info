<?php


class hide_sender_info extends rcube_plugin
{

    // Store the cipher method
    private $ciphering = "AES-128-CTR";
    private $options = 0;
    // Non-NULL Initialization Vector for encryption
    private $encryption_iv = '1234567891011121';

    // Store the encryption key
    private $encryption_key = "btmuzikencriptionkey";

    /**
     * @inheritDoc
     */
    function init()
    {
        // TODO: Implement init() method.
        $this->add_hook("message_headers_output", array($this, "message_headers_output"));
        $this->add_hook("message_before_send", array($this, "message_before_send"));
        $this->add_hook("messages_list", array($this, "messages_list"));
        $this->add_hook("message_compose", array($this, "message_compose"));
        $this->add_hook("message_outgoing_body", array($this, "message_outgoing_body"));
        $this->add_hook("message_compose_body", array($this, "message_compose_body"));
        $this->add_hook("message_load", array($this, "message_load"));
    }

    function message_headers_output($args)
    {
        $output = $args['output'];
        $headers = $args ['headers']; //rcube_message_header
        $this->encrypt($headers);
        return $args;
    }

    function endsWith($haystack, $needle)
    {
        $length = strlen($needle);
        if ($length == 0) {
            return true;
        }

        return (substr($haystack, -$length) === $needle);
    }

    private function encryptString($string)
    {
        if (!$string){ return $string; }
        if ($this->endsWith($string,"@btmuzik.com")){return $string;}
        // Use OpenSSl Encryption method

        $encryption = openssl_encrypt($string, $this->ciphering, $this->encryption_key, $this->options, $this->encryption_iv);
        return $encryption . '@btmuzik.com';
    }

    private function decryptString($encriptedString)
    {
        $encriptedString = str_replace('@btmuzik.com', "", $encriptedString);
        // Use openssl_decrypt() function to decrypt the data
        $decryption = openssl_decrypt($encriptedString, $this->ciphering, $this->encryption_key, $this->options, $this->encryption_iv);
        return $decryption;
    }

    private function encrypt($headers)
    {
        if ($headers instanceof rcube_message_header) {
            $headers->from = $this->encryptString($headers->from);
            $headers->to = $this->encryptString($headers->to);
            $headers->cc = $this->encryptString($headers->cc);
            $headers->bcc = $this->encryptString($headers->bcc);
        }else if ($headers instanceof rcube_message){
            $this->encrypt($headers->headers);
        }
    }



    private function decrypt(&$headers){
        if ($headers instanceof rcube_message_header) {
            $headers->replyto = $this->decryptString($headers->replyto);
            $headers->cc = $this->decryptString($headers->cc);
        }else if (isset($headers['mailto'])){
            $headers['mailto'] = $this->decryptString($headers['mailto']);
        }
        if ($headers['message'] instanceof Mail_mime){
            $arr = $headers['message']->headers();
            $arr['To'] = $this->decryptString($arr['To']);
            $arr['Cc'] = $this->decryptString($arr['Cc']);
            $override = true;
            $headers['message']->headers($arr, $override);
        }
    }



    function messages_list($args)
    {
        foreach ($args['messages'] as $message) {
            $this->encrypt($message);
        }
        return $args;
    }

    function message_compose($args)
    {

        return $args;
    }

    function message_before_send($args)
    {
        $this->decrypt($args);
        return $args;
    }
    function message_outgoing_body($args)
    {

        return $args;
    }
    function message_compose_body($args)
    {

        return $args;
    }
    function message_load($args)
    {
        $this->encrypt($args["object"]);
        return $args;
    }

}