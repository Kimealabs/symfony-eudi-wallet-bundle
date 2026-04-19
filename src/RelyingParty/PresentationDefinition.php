<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\RelyingParty;

/**
 * Represents an OpenID4VP Presentation Definition.
 * Describes what credentials and claims the Relying Party is requesting.
 */
final class PresentationDefinition
{
    private string $id;
    private array $inputDescriptors = [];

    private function __construct(string $id)
    {
        $this->id = $id;
    }

    public static function create(?string $id = null): self
    {
        return new self($id ?? bin2hex(random_bytes(16)));
    }

    /**
     * Request PID (Person Identification Data) attributes.
     *
     * @param string[] $attributes e.g. ['family_name', 'given_name', 'age_over_18']
     */
    public function requestPid(array $attributes = ['family_name', 'given_name', 'birth_date']): self
    {
        $fields = array_map(
            static fn (string $attr) => ['path' => ['$.'.$attr]],
            $attributes
        );

        $this->inputDescriptors[] = [
            'id' => 'eu.europa.ec.eudi.pid.1',
            'name' => 'EU PID',
            'format' => [
                'vc+sd-jwt' => ['alg' => ['ES256']],
                'mso_mdoc' => ['alg' => ['ES256']],
            ],
            'constraints' => [
                'limit_disclosure' => 'required',
                'fields' => $fields,
            ],
        ];

        return $this;
    }

    /**
     * Request a custom credential type with specific fields.
     */
    public function requestCredential(string $descriptorId, string $type, array $fields): self
    {
        $this->inputDescriptors[] = [
            'id' => $descriptorId,
            'name' => $type,
            'format' => [
                'vc+sd-jwt' => ['alg' => ['ES256']],
            ],
            'constraints' => [
                'limit_disclosure' => 'required',
                'fields' => array_map(
                    static fn (string $field) => ['path' => ['$.'.$field]],
                    $fields
                ),
            ],
        ];

        return $this;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'input_descriptors' => $this->inputDescriptors,
        ];
    }
}
