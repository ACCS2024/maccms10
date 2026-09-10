<?php
namespace app\common\util;

/** The CSV byte stream cannot be represented by the supported UTF-8 text contract. */
final class ImportTextException extends \RuntimeException
{
}
