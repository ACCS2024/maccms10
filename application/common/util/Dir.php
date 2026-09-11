<?php
namespace app\common\util;
class Dir implements \IteratorAggregate {

    private $_values = array();
    public $error = "";

    /**
     * 架构函数
     * @param string $path  目录路径
     */
    public function __construct($path = '', $pattern = '*') {
        if (!$path) return false;
        if (substr($path, -1) != "/") $path .= "/";
        $this->listFile($path, $pattern);
    }


    /**
     * 生成目录
     * @param  string  $path 目录
     * @param  integer $mode 权限
     * @return boolean
     */
    public static function create($path, $mode = 0755) {
      if(is_dir($path)) return TRUE;
      $path = str_replace("\\", "/", $path);
      if(substr($path, -1) != '/') $path = $path.'/';
      $temp = explode('/', $path);
      $cur_dir = '';
      $max = count($temp) - 1;
      for($i=0; $i<$max; $i++) {
        $cur_dir .= $temp[$i].'/';
        if (@is_dir($cur_dir)) continue;
        @mkdir($cur_dir, $mode, true);
        @chmod($cur_dir, $mode);
      }
      return is_dir($path);
    }

    /**
     * 取得目录下面的文件信息
     * @param mixed $pathname 路径
     */
    public function listFile($pathname, $pattern = '*') {
            $dir = array();
            $list = glob($pathname . $pattern) ?: [];
            foreach ($list as $i => $file) {
                //$dir[$i]['filename']    = basename($file);
                //basename取中文名出问题.改用此方法
                //编码转换.把中文的调整一下.
                $dir[$i]['filename'] = preg_replace('/^.+[\\\\\\/]/', '', $file);
                $dir[$i]['pathname'] = realpath($file);
                $dir[$i]['owner'] = fileowner($file);
                $dir[$i]['perms'] = fileperms($file);
                $dir[$i]['inode'] = fileinode($file);
                $dir[$i]['group'] = filegroup($file);
                $dir[$i]['path'] = dirname($file);
                $dir[$i]['atime'] = fileatime($file);
                $dir[$i]['ctime'] = filectime($file);
                $dir[$i]['size'] = filesize($file);
                $dir[$i]['type'] = filetype($file);
                $dir[$i]['ext'] = is_file($file) ? strtolower(pathinfo($file, PATHINFO_EXTENSION)) : '';
                $dir[$i]['mtime'] = filemtime($file);
                $dir[$i]['isDir'] = is_dir($file);
                $dir[$i]['isFile'] = is_file($file);
                $dir[$i]['isLink'] = is_link($file);
                $dir[$i]['isExecutable'] = is_executable($file);
                $dir[$i]['isReadable'] = is_readable($file);
                $dir[$i]['isWritable'] = is_writable($file);
            }
            // 对结果排序 保证目录在前面(闭包替代 PHP8 已移除的 create_function)
            usort($dir, function ($a, $b) {
                $k = 'isDir';
                if ($a[$k] == $b[$k]) {
                    return 0;
                }
                return $a[$k] > $b[$k] ? -1 : 1;
            });
            $this->_values = $dir;
    }

    /**
     * 返回数组中的当前元素（单元）
     * @return array
     */
    public static function current($arr) {
        if (!is_array($arr)) {
            return false;
        }
        return current($arr);
    }

    /**
     * 文件上次访问时间
     * @return integer
     */
    public function getATime() {
        $current = $this->current($this->_values);
        return $current['atime'] ?? false;
    }

    /**
     * 取得文件的 inode 修改时间
     * @return integer
     */
    public function getCTime() {
        $current = $this->current($this->_values);
        return $current['ctime'] ?? false;
    }

    /**
     * 遍历子目录文件信息
     * @return DirectoryIterator
     */
    public function getChildren() {
        $current = $this->current($this->_values);
        if (!empty($current['isDir'])) {
            return new Dir($current['pathname']);
        }
        return false;
    }

    /**
     * 取得文件名
     * @return string
     */
    public function getFilename() {
        $current = $this->current($this->_values);
        return $current['filename'] ?? false;
    }

    /**
     * 取得文件的组
     * @return integer
     */
    public function getGroup() {
        $current = $this->current($this->_values);
        return $current['group'] ?? false;
    }

    /**
     * 取得文件的 inode
     * @return integer
     */
    public function getInode() {
        $current = $this->current($this->_values);
        return $current['inode'] ?? false;
    }

    /**
     * 取得文件的上次修改时间
     * @return integer
     */
    public function getMTime() {
        $current = $this->current($this->_values);
        return $current['mtime'] ?? false;
    }

    /**
     * 取得文件的所有者
     * @return string
     */
    function getOwner() {
        $current = $this->current($this->_values);
        return $current['owner'] ?? false;
    }

    /**
     * 取得文件路径，不包括文件名
     * @return string
     */
    public function getPath() {
        $current = $this->current($this->_values);
        return $current['path'] ?? false;
    }

    /**
     * 取得文件的完整路径，包括文件名
     * @return string
     */
    public function getPathname() {
        $current = $this->current($this->_values);
        return $current['pathname'] ?? false;
    }

    /**
     * 取得文件的权限
     * @return integer
     */
    public function getPerms() {
        $current = $this->current($this->_values);
        return $current['perms'] ?? false;
    }

    /**
     * 取得文件的大小
     * @return integer
     */
    public function getSize() {
        $current = $this->current($this->_values);
        return $current['size'] ?? false;
    }

    /**
     * 取得文件类型
     * @return string
     */
    public function getType() {
        $current = $this->current($this->_values);
        return $current['type'] ?? false;
    }

    /**
     * 是否为目录
     * @return boolen
     */
    public function isDir() {
        $current = $this->current($this->_values);
        return $current['isDir'] ?? false;
    }

    /**
     * 是否为文件
     * @return boolen
     */
    public function isFile() {
        $current = $this->current($this->_values);
        return $current['isFile'] ?? false;
    }

    /**
     * 文件是否为一个符号连接
     * @return boolen
     */
    public function isLink() {
        $current = $this->current($this->_values);
        return $current['isLink'] ?? false;
    }

    /**
     * 文件是否可以执行
     * @return boolen
     */
    public function isExecutable() {
        $current = $this->current($this->_values);
        return $current['isExecutable'] ?? false;
    }

    /**
     * 文件是否可读
     * @return boolen
     */
    public function isReadable() {
        $current = $this->current($this->_values);
        return $current['isReadable'] ?? false;
    }

    /**
     * 获取foreach的遍历方式
     * @return string
     */
    public function getIterator(): \Traversable {
        return new \ArrayIterator($this->_values);
    }

    // 返回目录的数组信息
    public function toArray() {
        return $this->_values;
    }

    // 静态方法
    /**
     * 判断目录是否为空
     * @return void
     */
    public static function isEmpty($directory) {
        $handle = opendir($directory);
        while (($file = readdir($handle)) !== false) {
            if ($file != "." && $file != "..") {
                closedir($handle);
                return false;
            }
        }
        closedir($handle);
        return true;
    }

    /**
     * 取得目录中的结构信息
     * @return void
     */
    public static function getList($directory) {
        $scandir = scandir($directory);
        $dir = [];
        foreach ($scandir as $k => $v) {
            if ($v == '.' || $v == '..') {
                continue;
            }
            $dir[] = $v;
        }
        return $dir;
    }

    /** Validate path syntax without resolving away symbolic links or touching directory contents. */
    private static function cleanupDirectoryPath($directory): ?string {
        if (!is_string($directory) || $directory === '' || str_contains($directory, "\0") || str_contains($directory, '://')) {
            return null;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            if (str_starts_with($directory, '\\\\') || str_starts_with($directory, '//')) { return null; }
            $directory = str_replace('\\', '/', $directory);
        }
        // is_link("link/") follows the directory target on POSIX. Inspect the entry itself.
        $directory = rtrim($directory, '/');
        while (strlen($directory) > 1 && str_ends_with($directory, '/.')) {
            $directory = rtrim(substr($directory, 0, -2), '/');
        }
        if ($directory === '' || $directory === '.' || in_array('..', explode('/', $directory), true)
            || (DIRECTORY_SEPARATOR === '\\' && preg_match('/^[a-z]:$/iD', $directory))) { return null; }
        return $directory;
    }

    /** Delete the selected directory; symbolic links are removed as entries, never traversed. */
    public static function delDir($directory, $subdir = true): bool {
        return self::deleteDirectory($directory, false, true);
    }

    /** Remove a physical cache directory if present. A linked cache has not been cleared. */
    public static function clearDirectory($directory): bool {
        return self::deleteDirectory($directory, true, false);
    }

    private static function deleteDirectory($directory, bool $allowMissing, bool $removeLink): bool {
        $directory = self::cleanupDirectoryPath($directory);
        if ($directory === null) { return false; }
        // A linked parent can redirect the requested subtree even when its final entry is ordinary.
        $parent = dirname($directory);
        while (true) {
            clearstatcache(true, $parent);
            if (is_link($parent)) { return false; }
            // An inaccessible ancestor must not turn a stat failure into an "already absent" result.
            if (file_exists($parent) && (!is_dir($parent)
                || (DIRECTORY_SEPARATOR !== '\\' && !is_executable($parent)))) { return false; }
            $next = dirname($parent);
            if ($next === $parent) { break; }
            $parent = $next;
        }
        clearstatcache(true, $directory);
        if (is_link($directory)) {
            return $removeLink && @unlink($directory);
        }
        if (!is_dir($directory)) {
            return $allowMissing && !file_exists($directory);
        }
        $handle = @opendir($directory);
        if ($handle === false) {
            return false;
        }
        $ok = true;
        while (($file = readdir($handle)) !== false) {
            if ($file != "." && $file != "..") {
                $path = $directory . DIRECTORY_SEPARATOR . $file;
                $removed = !is_link($path) && is_dir($path) ? self::delDir($path) : @unlink($path);
                $ok = $removed && $ok;
            }
        }
        closedir($handle);
        return $ok && @rmdir($directory);
    }

    /**
     * 删除目录下面的所有文件，但不删除目录
     * @return void
     */
    public static function del($directory) {
        if (is_dir($directory) == false) {
            return false;
        }
        $handle = opendir($directory);
        while (($file = readdir($handle)) !== false) {
            if ($file != "." && $file != ".." && is_file("$directory/$file")) {
                unlink("$directory/$file");
            }
        }
        closedir($handle);
    }

    /**
     * 复制目录
     * @return void
     */
    public static function copyDir($source, $destination) {
        if (is_dir($source) == false) {
            return false;
        }
        if (is_dir($destination) == false) {
            mkdir($destination, 0755);
        }
        $handle = opendir($source);
        while (false !== ($file = readdir($handle))) {
            if ($file != "." && $file != "..") {
                if (is_dir("$source/$file")) {
                    Dir::copyDir("$source/$file", "$destination/$file");
                } else {
                    copy("$source/$file", "$destination/$file");
                }
            }
        }
        closedir($handle);
    }

}

?>
