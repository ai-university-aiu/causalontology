<?php

/* The exception an enforcing store raises when it refuses a write. */

declare(strict_types=1);

namespace Causalontology;

/** An enforcing store refused a write, with the reason as getMessage(). */
final class RejectedWrite extends \RuntimeException
{
}
