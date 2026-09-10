<?php
/** Scoped model clock for the crossing-midnight regression. Defaults to the real clock. */
namespace app\common\model;
function time(): int { return $GLOBALS['task_model_clock'] ?? \time(); }
function date(string $format, ?int $timestamp = null): string { return \date($format, $timestamp ?? time()); }
