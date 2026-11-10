<?php

declare(strict_types=1);

require_once(__DIR__ . '/config.inc');
require_once(__DIR__ . '/pfsense-utils.inc');
require_once(__DIR__ . '/services.inc');
require_once(__DIR__ . '/util.inc');

/** @var array<string, mixed> $sinkholeStubGlobalValues @since 1.0.0 */
$sinkholeStubGlobalValues = [];

/**
 * Sinkhole Stub - Global Value.
 *
 * @param string $key - pfSense global key.
 *
 * @return mixed
 *
 * @since 1.0.0
 */
function g_get(string $key): mixed
{
    global $sinkholeStubGlobalValues;

    return $sinkholeStubGlobalValues[$key] ?? null;
}

/**
 * Sinkhole Stub - Get User Entry.
 *
 * @param string $username - Logged-in username.
 *
 * @return array{item: array{name: string, priv: list<string>}}
 *
 * @since 1.0.0
 */
function getUserEntry(string $username): array
{
    global $sinkholeStubUserPrivileges;

    return [
        'item' => [
            'name' => $username,
            'priv' => $sinkholeStubUserPrivileges,
        ],
    ];
}

/**
 * Sinkhole Stub - User Has Privilege.
 *
 * @param array{name?: string, priv?: list<string>} $userEntry - User entry.
 * @param string|false $privilegeIdentifier - Privilege identifier.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function userHasPrivilege(
    array $userEntry,
    string|false $privilegeIdentifier = false,
): bool {
    return is_string($privilegeIdentifier)
        && in_array($privilegeIdentifier, $userEntry['priv'] ?? [], true);
}

/** @since 1.0.0 */
function display_top_tabs(array $tabs): void
{
    unset($tabs);
}

/** @since 1.0.0 */
function print_info_box(
    string $message,
    string $class = 'info',
    bool $dismissible = true,
): void {
    unset($dismissible);
    print('<div class="alert alert-'
        . htmlspecialchars($class, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        . '">'
        . $message
        . '</div>');
}

/**
 * Minimal pfSense form element for offline page rendering.
 *
 * @since 1.0.0
 */
class SinkholeStubFormElement
{
    /** @var list<string> @since 1.0.0 */
    protected array $classes = [];

    /** @var array<string, mixed> @since 1.0.0 */
    protected array $attributes = [];

    /** @since 1.0.0 */
    public function addClass(string ...$classes): static
    {
        foreach ($classes as $class) {
            if (!in_array($class, $this->classes, true)) {
                $this->classes[] = $class;
            }
        }

        return $this;
    }

    /** @since 1.0.0 */
    public function removeClass(string $class): static
    {
        $this->classes = array_values(array_filter(
            $this->classes,
            static fn(string $candidate): bool => $candidate !== $class,
        ));

        return $this;
    }

    /** @since 1.0.0 */
    public function setAttribute(string $key, mixed $value = null): static
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    /**
     * @param array<string, mixed> $attributes - Attributes.
     *
     * @since 1.0.0
     */
    protected function renderAttributes(array $attributes = []): string
    {
        if ($this->classes !== []) {
            $attributes = ['class' => implode(' ', $this->classes)] + $attributes;
        }
        $attributes = array_replace($attributes, $this->attributes);
        $rendered = '';

        foreach ($attributes as $key => $value) {
            if ($value === null || $value === false) {
                continue;
            }
            $rendered .= ' ' . $key;

            if ($value !== true) {
                $rendered .= '="' . self::escape((string) $value) . '"';
            }
        }

        return $rendered;
    }

    /** @since 1.0.0 */
    protected static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

/**
 * Minimal pfSense form input.
 *
 * @since 1.0.0
 */
class Form_Input extends SinkholeStubFormElement
{
    /** @since 1.0.0 */
    protected mixed $name;

    /** @since 1.0.0 */
    protected mixed $title;

    /** @since 1.0.0 */
    protected mixed $type;

    /** @since 1.0.0 */
    protected mixed $value;

    /** @since 1.0.0 */
    protected ?string $help = null;

    /** @since 1.0.0 */
    protected ?int $width = null;

    /**
     * @param array<string, mixed> $attributes - Attributes.
     *
     * @since 1.0.0
     */
    public function __construct(
        mixed $name,
        mixed $title,
        mixed $type = 'text',
        mixed $value = null,
        array $attributes = [],
    ) {
        $this->name = $name;
        $this->title = $title;
        $this->type = $type;
        $this->value = $value;
        $this->attributes = $attributes;
        $this->classes = ['form-control'];
    }

    /** @since 1.0.0 */
    public function getTitle(): mixed
    {
        return $this->title;
    }

    /** @since 1.0.0 */
    public function getType(): mixed
    {
        return $this->type;
    }

    /** @since 1.0.0 */
    public function getId(): string
    {
        return is_string($this->name) ? $this->name : '';
    }

    /** @since 1.0.0 */
    public function getWidth(): ?int
    {
        return $this->width;
    }

    /** @since 1.0.0 */
    public function setHelp(string $help, mixed ...$arguments): static
    {
        $this->help = ($arguments === []) ? $help : sprintf($help, ...$arguments);

        return $this;
    }

    /** @since 1.0.0 */
    public function setRows(int $rows): static
    {
        $this->attributes['rows'] = $rows;

        return $this;
    }

    /** @since 1.0.0 */
    public function setWidth(int $width): static
    {
        $this->width = $width;

        return $this;
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        $attributes = [
            'name' => $this->name,
            'id' => $this->getId(),
            'type' => $this->type,
            'value' => $this->value,
        ];

        return '<input' . $this->renderAttributes($attributes) . '>';
    }

    /** @since 1.0.0 */
    public function __toString(): string
    {
        $control = $this->renderControl();

        if ($this->type === 'hidden') {
            return $control;
        }

        if ($this->width === null && $this->help === null) {
            return $control;
        }
        $help = ($this->help === null)
            ? ''
            : '<span class="help-block">' . $this->help . '</span>';

        return '<div class="col-sm-' . ($this->width ?? 10) . '">'
            . $control
            . $help
            . '</div>';
    }
}

/**
 * Minimal pfSense select input.
 *
 * @since 1.0.0
 */
class Form_Select extends Form_Input
{
    /** @var array<array-key, mixed> @since 1.0.0 */
    private array $values;

    /** @since 1.0.0 */
    private bool $multiple;

    /**
     * @param array<array-key, mixed> $values - Options.
     *
     * @since 1.0.0
     */
    public function __construct(
        mixed $name,
        mixed $title,
        mixed $value,
        array $values,
        bool $allowMultiple = false,
    ) {
        parent::__construct(
            $allowMultiple ? (string) $name . '[]' : $name,
            $title,
            null,
            $value,
        );
        $this->values = $values;
        $this->multiple = $allowMultiple;
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        $options = '';

        foreach ($this->values as $value => $label) {
            $selected = $this->multiple
                ? in_array((string) $value, array_map('strval', (array) $this->value), true)
                : (string) $this->value === (string) $value;
            $options .= '<option value="' . self::escape((string) $value) . '"'
                . ($selected ? ' selected' : '')
                . '>'
                . self::escape((string) $label)
                . '</option>';
        }
        $attributes = [
            'name' => $this->name,
            'id' => $this->getId(),
            'multiple' => $this->multiple ? 'multiple' : null,
        ];

        return '<select' . $this->renderAttributes($attributes) . '>'
            . $options
            . '</select>';
    }
}

/**
 * Minimal pfSense checkbox input.
 *
 * @since 1.0.0
 */
class Form_Checkbox extends Form_Input
{
    /** @since 1.0.0 */
    private string $description;

    /** @since 1.0.0 */
    private bool $checked;

    /** @since 1.0.0 */
    public function __construct(
        mixed $name,
        mixed $title,
        string $description,
        mixed $checked,
        mixed $value = 'yes',
    ) {
        parent::__construct($name, $title, 'checkbox', $value);
        $this->description = $description;
        $this->checked = (bool) $checked;
        $this->classes = [];
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        $attributes = [
            'name' => $this->name,
            'id' => $this->getId(),
            'type' => 'checkbox',
            'value' => $this->value,
            'checked' => $this->checked ? 'checked' : null,
        ];

        return '<label class="chkboxlbl"><input'
            . $this->renderAttributes($attributes)
            . '> '
            . self::escape($this->description)
            . '</label>';
    }
}

/**
 * Minimal pfSense textarea input.
 *
 * @since 1.0.0
 */
class Form_Textarea extends Form_Input
{
    /** @since 1.0.0 */
    public function __construct(mixed $name, mixed $title, mixed $value)
    {
        parent::__construct($name, $title, null, $value, ['rows' => 5]);
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        $attributes = [
            'name' => $this->name,
            'id' => $this->getId(),
        ];

        return '<textarea'
            . $this->renderAttributes($attributes)
            . '>'
            . self::escape((string) $this->value)
            . '</textarea>';
    }
}

/**
 * Minimal pfSense static-text input.
 *
 * @since 1.0.0
 */
class Form_StaticText extends Form_Input
{
    /** @since 1.0.0 */
    public function __construct(mixed $title, mixed $text)
    {
        parent::__construct(null, $title, 'text');
        $this->value = $text;
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        return (string) $this->value;
    }
}

/**
 * Minimal pfSense button input.
 *
 * @since 1.0.0
 */
class Form_Button extends Form_Input
{
    /** @since 1.0.0 */
    private ?string $link;

    /** @since 1.0.0 */
    private ?string $icon;

    /** @since 1.0.0 */
    public function __construct(
        mixed $name,
        string $title,
        ?string $link = null,
        ?string $icon = null,
    ) {
        parent::__construct($name, $title, null, $title);
        $this->classes = ['btn'];
        $this->link = $link;
        $this->icon = $icon;

        if ($link !== null) {
            $this->addClass('btn-default');
        } elseif ($icon === null) {
            $this->addClass('btn-primary');
        }
    }

    /** @since 1.0.0 */
    protected function renderControl(): string
    {
        $icon = ($this->icon === null)
            ? ''
            : '<i class="' . self::escape($this->icon) . ' icon-embed-btn"> </i>';

        if ($this->link !== null) {
            return '<a'
                . $this->renderAttributes([
                    'id' => $this->getId(),
                    'href' => $this->link,
                ])
                . '>'
                . $icon
                . self::escape((string) $this->title)
                . '</a>';
        }

        if ($this->icon === null) {
            return '<input'
                . $this->renderAttributes([
                    'name' => $this->name,
                    'id' => $this->getId(),
                    'type' => 'submit',
                    'value' => $this->value,
                ])
                . '>';
        }

        return '<button'
            . $this->renderAttributes([
                'name' => $this->name,
                'id' => $this->getId(),
                'type' => 'submit',
                'value' => $this->value,
            ])
            . '>'
            . $icon
            . self::escape((string) $this->title)
            . '</button>';
    }
}

/**
 * Minimal pfSense form group.
 *
 * @since 1.0.0
 */
class Form_Group extends SinkholeStubFormElement
{
    /** @since 1.0.0 */
    private string $title;

    /** @var list<Form_Input> @since 1.0.0 */
    private array $inputs = [];

    /** @since 1.0.0 */
    private ?string $help = null;

    /** @since 1.0.0 */
    public function __construct(mixed $title)
    {
        $this->title = (string) $title;
    }

    /** @since 1.0.0 */
    public function add(Form_Input $input): Form_Input
    {
        $this->inputs[] = $input;

        return $input;
    }

    /** @since 1.0.0 */
    public function setHelp(string $help, mixed ...$arguments): static
    {
        $this->help = ($arguments === []) ? $help : sprintf($help, ...$arguments);

        return $this;
    }

    /** @since 1.0.0 */
    public function __toString(): string
    {
        $spaceLeft = 10;
        $missingWidth = [];

        foreach ($this->inputs as $input) {
            if ($input->getWidth() === null) {
                $missingWidth[] = $input;
            } else {
                $spaceLeft -= $input->getWidth();
            }
        }

        if ($missingWidth !== []) {
            $width = max(1, intdiv($spaceLeft, count($missingWidth)));

            foreach ($missingWidth as $input) {
                $input->setWidth($width);
            }
        }
        $target = $this->inputs[0] ?? null;
        $for = ($target instanceof Form_Input && $target->getType() !== 'hidden')
            ? ' for="' . self::escape($target->getId()) . '"'
            : '';
        $title = self::escape($this->title);

        if (str_starts_with($title, '*')) {
            $title = '<span class="element-required">' . substr($title, 1) . '</span>';
        } elseif ($title !== '') {
            $title = '<span>' . $title . '</span>';
        }
        $help = ($this->help === null)
            ? ''
            : '<div class="col-sm-10 col-sm-offset-2"><span class="help-block">'
                . $this->help
                . '</span></div>';

        return '<div class="form-group">'
            . '<label class="col-sm-2 control-label"' . $for . '>'
            . $title
            . '</label>'
            . implode('', array_map('strval', $this->inputs))
            . $help
            . '</div>';
    }
}

/**
 * Minimal pfSense form section.
 *
 * @since 1.0.0
 */
class Form_Section extends SinkholeStubFormElement
{
    /** @since 1.0.0 */
    private string $title;

    /** @var list<Form_Group> @since 1.0.0 */
    private array $groups = [];

    /** @since 1.0.0 */
    public function __construct(mixed $title, string $id = '', int $collapsible = 0)
    {
        unset($id, $collapsible);
        $this->title = (string) $title;
    }

    /** @since 1.0.0 */
    public function add(Form_Group $group): Form_Group
    {
        $this->groups[] = $group;

        return $group;
    }

    /** @since 1.0.0 */
    public function addInput(Form_Input $input): Form_Input
    {
        $group = new Form_Group($input->getTitle());
        $group->add($input);
        $this->add($group);

        return $input;
    }

    /** @since 1.0.0 */
    public function __toString(): string
    {
        return '<div class="panel panel-default">'
            . '<div class="panel-heading"><h2 class="panel-title">'
            . self::escape($this->title)
            . '</h2></div>'
            . '<div class="panel-body">'
            . implode('', array_map('strval', $this->groups))
            . '</div></div>';
    }
}

/**
 * Minimal pfSense form.
 *
 * @since 1.0.0
 */
class Form extends SinkholeStubFormElement
{
    /** @var list<Form_Section> @since 1.0.0 */
    private array $sections = [];

    /** @var list<Form_Input> @since 1.0.0 */
    private array $globals = [];

    /** @since 1.0.0 */
    private string $method = 'post';

    /** @since 1.0.0 */
    private string $action;

    /** @since 1.0.0 */
    public function __construct(mixed $submit = null, bool $enabled = true)
    {
        unset($enabled);
        $this->action = (string) ($_SERVER['REQUEST_URI'] ?? '');

        if ($submit === null || is_string($submit)) {
            $button = new Form_Button(
                'save',
                is_string($submit) ? $submit : 'Save',
                null,
                'fa-solid fa-save',
            );
            $button->addClass('btn-primary');
            $this->addGlobal($button);
        } elseif ($submit instanceof Form_Input) {
            $this->addGlobal($submit);
        }
    }

    /** @since 1.0.0 */
    public function add(Form_Section $section): Form_Section
    {
        $this->sections[] = $section;

        return $section;
    }

    /** @since 1.0.0 */
    public function addGlobal(Form_Input $input): Form_Input
    {
        $this->globals[] = $input;

        return $input;
    }

    /** @since 1.0.0 */
    public function setAction(string $action): static
    {
        $this->action = $action;

        return $this;
    }

    /** @since 1.0.0 */
    public function setMethod(string $method): static
    {
        $this->method = $method;

        return $this;
    }

    /** @since 1.0.0 */
    public function __toString(): string
    {
        $hidden = '';
        $buttons = '';

        foreach ($this->globals as $global) {
            if ($global instanceof Form_Button) {
                $buttons .= (string) $global;
            } else {
                $hidden .= (string) $global;
            }
        }

        if ($buttons !== '') {
            $buttons = '<div class="col-sm-10 col-sm-offset-2">' . $buttons . '</div>';
        }

        return '<form class="form-horizontal" method="'
            . self::escape($this->method)
            . '" action="'
            . self::escape($this->action)
            . '" data-sinkhole-test-form>'
            . implode('', array_map('strval', $this->sections))
            . $hidden
            . $buttons
            . '</form>';
    }
}
