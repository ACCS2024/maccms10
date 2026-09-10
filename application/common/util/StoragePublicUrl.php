<?php
declare(strict_types=1);
namespace app\common\util;

/** A server-configured destination, never an allowlist inferred from a provider response. */
final class StoragePublicUrl
{
    public const PROVIDERS = ['s3','upyun','qiniu','ftp','alibaba','uomg','weibo'];
    private function __construct(public readonly string $provider, private readonly array $settings,
        public readonly string $fingerprint) {}

    public static function configured(string $provider, array $settings): self
    {
        if (!in_array($provider,self::PROVIDERS,true)) { throw new \InvalidArgumentException('Unsupported storage provider'); }
        $identity=['provider'=>$provider];
        foreach (match($provider) {
            's3'=>['bucket','region','endpoint','basepath','domain'],
            'ftp'=>['host','port','path','url'],
            'upyun','qiniu'=>['bucket','url'],
            default=>['public_url_prefix'],
        } as $key) {
            $value=$settings[$key]??'';
            if (!is_string($value) && !is_int($value)) { throw new \InvalidArgumentException('Invalid storage destination'); }
            $value=(string)$value;
            if (strlen($value)>2048 || preg_match('/[\x00-\x20\x7f]/',$value)) { throw new \InvalidArgumentException('Invalid storage destination'); }
            $identity[$key]=$value;
        }
        $instance=new self($provider,$identity,hash('sha256',json_encode($identity,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)));
        // A placeholder key checks the configured public URL without making an HTTP request.
        $instance->expected('upload/probe/fixture.jpg');
        return $instance;
    }

    public static function current(string $provider): self
    {
        $settings=$GLOBALS['config']['upload']['api'][$provider]??null;
        if (!is_array($settings)) { throw new \InvalidArgumentException('Storage destination is not configured'); }
        return self::configured($provider,$settings);
    }

    public function expected(string $localPath): string
    {
        if (!self::localPath($localPath)) { throw new \InvalidArgumentException('Invalid storage object path'); }
        if ($this->provider==='s3') {
            $bucket=$this->settings['bucket'];$region=$this->settings['region'];$base=$this->settings['basepath'];
            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/D',$bucket)
                || !preg_match('/^[a-z0-9-]{1,63}$/D',$region)
                || !preg_match('~^[A-Za-z0-9_./-]{0,512}$~D',$base)
                || in_array('..',explode('/',$base),true) || in_array('.',explode('/',$base),true)) {
                throw new \InvalidArgumentException('Invalid S3 object destination');
            }
            // Match the existing adapter's exact key, including a configured leading slash and PHP's legacy '0' case.
            $key=(!empty($base)?rtrim($base,'/').'/':'').$localPath;
            if ($this->settings['domain']!=='') {
                $url=rtrim($this->settings['domain'],'/').'/'.$bucket.'/'.$key;
            } else {
                $options=['region'=>$region,'version'=>'2006-03-01','credentials'=>['key'=>'policy-only','secret'=>'policy-only']];
                if ($this->settings['endpoint']!=='') {
                    if (!self::validUrl($this->settings['endpoint'])) { throw new \InvalidArgumentException('Invalid S3 endpoint'); }
                    $options['endpoint']=$this->settings['endpoint'];$options['use_path_style_endpoint']=true;
                }
                // AWS constructs this URL locally from endpoint/bucket/key; no credentials are resolved or sent.
                $url=(new \Aws\S3\S3Client($options))->getObjectUrl($bucket,$key);
            }
        } elseif (in_array($this->provider,['upyun','qiniu','ftp'],true)) {
            $url=rtrim($this->settings['url'],'/').'/'.$localPath;
        } else {
            // Unowned image services require an explicit server-managed public prefix before the new API may call them.
            $prefix=$this->settings['public_url_prefix'];
            if (!self::validUrl($prefix)) { throw new \InvalidArgumentException('A trusted image service URL prefix is required'); }
            $url=rtrim($prefix,'/').'/'.$localPath;
        }
        if (!self::validUrl($url)) { throw new \InvalidArgumentException('Invalid public storage URL'); }
        return $url;
    }

    public function accepts(mixed $url,string $localPath): bool
    {
        if (!is_string($url) || !self::validUrl($url)) { return false; }
        if (in_array($this->provider,['s3','upyun','qiniu','ftp'],true)) {
            return hash_equals($this->expected($localPath),$url);
        }
        $prefix=rtrim($this->settings['public_url_prefix'],'/').'/';
        return str_starts_with($url,$prefix);
    }

    public static function localPath(mixed $path): bool
    {
        return is_string($path) && strlen($path)<=255
            && preg_match('~^upload/[a-z0-9_]{1,64}/[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$~D',$path)===1
            && !in_array('..',explode('/',$path),true) && !in_array('.',explode('/',$path),true)
            && !str_contains($path,'//') && !str_ends_with($path,'/');
    }

    public static function validUrl(string $url): bool
    {
        if ($url==='' || strlen($url)>2048 || preg_match('/[^\x21-\x7e]/',$url) || str_contains($url,'\\')
            || strpbrk($url, "\"'<>`")!==false) { return false; }
        $parts=parse_url($url);
        if (!is_array($parts) || filter_var($url,FILTER_VALIDATE_URL)===false
            || preg_match('/%(?:2f|5c|25)/i',$parts['path']??'')
            || in_array('..',explode('/',rawurldecode($parts['path']??'')),true)
            || in_array('.',explode('/',rawurldecode($parts['path']??'')),true)) { return false; }
        return is_array($parts) && in_array($parts['scheme']??'', ['http','https'],true)
            && isset($parts['host']) && $parts['host']!==''
            && !array_key_exists('user',$parts) && !array_key_exists('pass',$parts)
            && !array_key_exists('fragment',$parts) && !array_key_exists('query',$parts)
            && preg_match('/%(?:0[0-9a-f]|1[0-9a-f]|7f)/i',$url)!==1;
    }
}
