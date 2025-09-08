// AnonCredsClient.cs
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using AnonCredsNet.Exceptions;
// using AnonCredsNet.Helpers; // obsolete after consolidation
using AnonCredsNet.Interop;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;

namespace AnonCredsNet;

public class AnonCredsClient
{
    public AnonCredsClient()
    {
        // Placeholder for initialization if needed
    }

    /// <summary>
    /// Generates a cryptographically secure nonce for use in presentation requests.
    /// </summary>
    public static string GenerateNonce()
    {
        return AnonCredsHelpers.GenerateNonce();
    }

    public Presentation CreatePresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string? revRegsJson,
        string? revListsJson
    )
    {
        // Derive schema and cred def IDs from the provided JSON maps if not explicitly provided
        string? schemaIdsJson = null;
        string? credDefIdsJson = null;

        try
        {
            var schemaMap = JsonSerializer.Deserialize<Dictionary<string, string>>(schemasJson);
            if (schemaMap != null)
                schemaIdsJson = JsonSerializer.Serialize(schemaMap.Keys.ToArray());
        }
        catch
        { /* leave null if not a map */
        }

        try
        {
            var credDefMap = JsonSerializer.Deserialize<Dictionary<string, string>>(credDefsJson);
            if (credDefMap != null)
                credDefIdsJson = JsonSerializer.Serialize(credDefMap.Keys.ToArray());
        }
        catch
        { /* leave null if not a map */
        }

        var (presentation, _, _, _, _, _, _, _, _, _) = CreatePresentation(
            presReq,
            credentialsJson,
            selfAttestJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson
        );
        return presentation;
    }

    public (
        Presentation presentation,
        FfiStrList schemaIds,
        FfiObjectHandleList schemas,
        FfiStrList credDefIds,
        FfiObjectHandleList credDefs,
        FfiStrList revRegIds,
        FfiObjectHandleList revRegs,
        FfiStrList revListIds,
        FfiObjectHandleList revLists,
        FfiCredentialEntryList credentials
    ) CreatePresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string? schemaIdsJson,
        string? credDefIdsJson,
        string? revRegsJson,
        string? revListsJson
    )
    {
        Console.WriteLine("   DEBUG: Entering CreatePresentation");
        if (
            presReq == null
            || string.IsNullOrEmpty(credentialsJson)
            || string.IsNullOrEmpty(linkSecret)
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
            || string.IsNullOrEmpty(schemaIdsJson)
            || string.IsNullOrEmpty(credDefIdsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");

        Console.WriteLine("   DEBUG: Creating schemas list from JSON");
        var (schemasList, schemasObjects) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        Console.WriteLine("   DEBUG: Created schemas list successfully");

        Console.WriteLine("   DEBUG: Creating credDefs list from JSON");
        var (credDefsList, credDefsObjects) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        Console.WriteLine("   DEBUG: Created credDefs list successfully");

        Console.WriteLine("   DEBUG: Parsing credentials JSON");
        FfiCredentialEntryList credentialsList = ParseCredentialsJson(credentialsJson);
        Console.WriteLine("   DEBUG: Parsed credentials JSON successfully");
        // Debug each entry for timestamp/rev_state presence
        try
        {
            var dbgEntries = System.Text.Json.JsonSerializer.Deserialize<CredentialEntryJson[]>(
                credentialsJson
            );
            if (dbgEntries != null)
            {
                foreach (var e in dbgEntries)
                {
                    Console.WriteLine(
                        $"DEBUG Credentials entry -> Timestamp: {e.Timestamp?.ToString() ?? "<null>"}, RevState: {(string.IsNullOrEmpty(e.RevState) ? 0 : 1)}"
                    );
                }
            }
        }
        catch { }

        Console.WriteLine("   DEBUG: Creating schema IDs list");
        var schemaIds = AnonCredsHelpers.CreateFfiStrList(schemaIdsJson);
        Console.WriteLine("   DEBUG: Created schema IDs list successfully");

        Console.WriteLine("   DEBUG: Creating credDef IDs list");
        var credDefIds = AnonCredsHelpers.CreateFfiStrList(credDefIdsJson);
        Console.WriteLine("   DEBUG: Created credDef IDs list successfully");

        var revRegIds = new FfiStrList();
        var revRegsList = new FfiObjectHandleList();
        var revListsList = new FfiObjectHandleList();

        if (!string.IsNullOrEmpty(revRegsJson))
        {
            var (revRegs, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                revRegsJson,
                RevocationRegistryDefinition.FromJson
            );
            revRegsList = revRegs;
        }

        if (!string.IsNullOrEmpty(revListsJson))
        {
            var (revLists, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                revListsJson,
                RevocationStatusList.FromJson
            );
            revListsList = revLists;
        }

        Console.WriteLine("   DEBUG: Creating credentials prove list");
        // Create credentials_prove list based on presentation request, excluding self-attested referents
        var credentialsProve = CreateCredentialsProveList(
            presReq.ToJson(),
            selfAttestJson,
            credentialsJson
        );
        Console.WriteLine("   DEBUG: Created credentials prove list successfully");

        var selfAttestNames = new FfiStrList();
        var selfAttestValues = new FfiStrList();

        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            var selfAttested =
                JsonSerializer.Deserialize<Dictionary<string, string>>(selfAttestJson)
                ?? new Dictionary<string, string>();
            selfAttestNames = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Keys.ToArray()
            );
            selfAttestValues = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Values.ToArray()
            );
        }

        // Debug: dump first credential entry
        if (credentialsList.Count.ToUInt32() > 0)
        {
            var entryPtr = credentialsList.Data;
            var entry = Marshal.PtrToStructure<FfiCredentialEntry>(entryPtr);
            Console.WriteLine(
                $"DEBUG Credentials entry -> Timestamp: {entry.Timestamp}, RevState: {entry.RevState}"
            );
        }

        var presentation = Presentation.Create(
            presReq.Handle,
            credentialsList,
            credentialsProve,
            selfAttestNames,
            selfAttestValues,
            linkSecret,
            schemasList,
            schemaIds,
            credDefsList,
            credDefIds
        );

        return (
            presentation,
            schemaIds,
            schemasList,
            credDefIds,
            credDefsList,
            revRegIds,
            revRegsList,
            new FfiStrList(),
            revListsList,
            credentialsList
        );
    }

    public bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string? revRegDefsJson,
        string? revStatusListsJson,
        string? nonRevocJson
    )
    {
        // Extract IDs from the objects - this is a temporary approach since the objects don't contain IDs
        // In a real implementation, the IDs should be passed separately
        throw new NotImplementedException("Use overload that accepts ID arrays");
    }

    public bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson = null,
        string? revStatusListsJson = null,
        string? revRegDefIdsJson = null,
        string? nonRevocJson = null
    )
    {
        return AnonCredsHelpers.VerifyPresentation(
            presentation,
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegDefsJson,
            revStatusListsJson,
            revRegDefIdsJson,
            nonRevocJson
        );
    }

    public Credential IssueCredential(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        string? revRegId,
        CredentialRevocationConfig? revConfig,
        string? tailsPath
    )
    {
        if (
            credDef == null
            || credDefPvt == null
            || offer == null
            || request == null
            || string.IsNullOrEmpty(credValues)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");

        var (credential, _) = Credential.Create(
            credDef,
            credDefPvt,
            offer,
            request,
            credValues,
            revRegId,
            tailsPath,
            revConfig?.RevStatusList,
            revConfig
        );
        return credential;
    }

    // W3C: Issue credential in W3C form
    public W3cCredential IssueW3cCredential(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        CredentialRevocationConfig? revConfig,
        string? w3cVersion = null
    )
    {
        return W3cCredential.Create(
            credDef,
            credDefPvt,
            offer,
            request,
            credValues,
            revConfig,
            w3cVersion
        );
    }

    public (
        W3cPresentation presentation,
        FfiStrList schemaIds,
        FfiObjectHandleList schemas,
        FfiStrList credDefIds,
        FfiObjectHandleList credDefs,
        FfiCredentialEntryList credentials
    ) CreateW3cPresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string? schemaIdsJson,
        string? credDefIdsJson,
        string? w3cVersion = null
    )
    {
        if (
            presReq == null
            || string.IsNullOrEmpty(credentialsJson)
            || string.IsNullOrEmpty(linkSecret)
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
        )
            throw new ArgumentNullException("Invalid inputs");

        var (schemasList, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        var (credDefsList, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var credentialsList = ParseCredentialsJson(credentialsJson, isW3c: true);

        var schemaIds = !string.IsNullOrEmpty(schemaIdsJson)
            ? AnonCredsHelpers.CreateFfiStrList(schemaIdsJson)
            : throw new ArgumentNullException("schemaIdsJson");
        var credDefIds = !string.IsNullOrEmpty(credDefIdsJson)
            ? AnonCredsHelpers.CreateFfiStrList(credDefIdsJson)
            : throw new ArgumentNullException("credDefIdsJson");

        var credentialsProve = CreateCredentialsProveList(presReq.ToJson(), null, credentialsJson);

        var presentation = W3cPresentation.Create(
            presReq.Handle,
            credentialsList,
            credentialsProve,
            linkSecret,
            schemasList,
            schemaIds,
            credDefsList,
            credDefIds,
            w3cVersion
        );

        return (presentation, schemaIds, schemasList, credDefIds, credDefsList, credentialsList);
    }

    public bool VerifyW3cPresentation(
        W3cPresentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson = null,
        string? revStatusListsJson = null,
        string? revRegDefIdsJson = null,
        string? nonRevocJson = null
    )
    {
        // Reuse the same helper structure for list creation and IDs
        Console.WriteLine("Starting VerifyW3cPresentation...");
        try
        {
            var (schemasList, schemasObjects) =
                AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(schemasJson, Schema.FromJson);
            var (credDefsList, credDefsObjects) =
                AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                    credDefsJson,
                    CredentialDefinition.FromJson
                );
            var schemaIds = AnonCredsHelpers.CreateFfiStrList(schemaIdsJson);
            var credDefIds = AnonCredsHelpers.CreateFfiStrList(credDefIdsJson);

            var (revRegDefsList, revRegDefsObjects) = string.IsNullOrEmpty(revRegDefsJson)
                ? (
                    new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                    Array.Empty<RevocationRegistryDefinition>()
                )
                : AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                    revRegDefsJson,
                    RevocationRegistryDefinition.FromJson
                );

            var (revStatusLists, revStatusObjects) = string.IsNullOrEmpty(revStatusListsJson)
                ? (
                    new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                    Array.Empty<RevocationStatusList>()
                )
                : AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                    revStatusListsJson,
                    RevocationStatusList.FromJson
                );

            // Always create revRegDefIds if provided, independent of revRegDefs object list
            var revRegDefIds = !string.IsNullOrEmpty(revRegDefIdsJson)
                ? AnonCredsHelpers.CreateFfiStrList(revRegDefIdsJson)
                : new FfiStrList { Count = 0, Data = IntPtr.Zero };

            var nonRevocList = AnonCredsHelpers.BuildNonrevokedIntervalOverrideList(nonRevocJson);

            var code = NativeMethods.anoncreds_verify_w3c_presentation(
                presentation.Handle,
                presReq.Handle,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                revRegDefsList,
                revRegDefIds,
                revStatusLists,
                nonRevocList,
                out var valid
            );
            if (code != ErrorCode.Success)
            {
                // Align with Python semantics: treat common verify-time issues as invalid=false
                var err = AnonCredsHelpers.GetCurrentError();
                if (
                    !string.IsNullOrEmpty(err)
                    && (
                        err.Contains("Invalid timestamp", StringComparison.OrdinalIgnoreCase)
                        || err.Contains("proof rejected", StringComparison.OrdinalIgnoreCase)
                        || err.Contains("credential revoked", StringComparison.OrdinalIgnoreCase)
                        || err.Contains(
                            "Revocation Registry not provided",
                            StringComparison.OrdinalIgnoreCase
                        )
                    )
                )
                {
                    Console.WriteLine($"Verification returned error: {err}");
                    Console.WriteLine("Interpreting verification error as invalid=false");
                    return false;
                }
                throw new AnonCredsException(code, err);
            }
            return valid != 0;
        }
        finally
        {
            // Free all lists and dispose created objects
            // Note: keep this minimal here; extended debug/logging already exists in classic path
        }
    }

    private static FfiCredentialEntryList ParseCredentialsJson(
        string credentialsJson,
        bool isW3c = false
    )
    {
        var entries =
            JsonSerializer.Deserialize<CredentialEntryJson[]>(
                credentialsJson,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            ) ?? throw new InvalidOperationException("Invalid credentials JSON");
        var ffiEntries = new FfiCredentialEntry[entries.Length];
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            var credBuffer = AnonCredsHelpers.CreateByteBuffer(entry.Credential);
            long credHandle;
            ErrorCode result;
            try
            {
                if (isW3c)
                {
                    result = NativeMethods.anoncreds_w3c_credential_from_json(
                        credBuffer,
                        out credHandle
                    );
                }
                else
                {
                    result = NativeMethods.anoncreds_credential_from_json(
                        credBuffer,
                        out credHandle
                    );
                }
            }
            finally
            {
                AnonCredsHelpers.FreeByteBuffer(credBuffer);
            }
            if (result != ErrorCode.Success)
                throw new AnonCredsException(result, AnonCredsHelpers.GetCurrentError());

            long revStateHandle = 0;
            if (!string.IsNullOrEmpty(entry.RevState))
            {
                var revStateBuffer = AnonCredsHelpers.CreateByteBuffer(entry.RevState);
                try
                {
                    result = NativeMethods.anoncreds_revocation_state_from_json(
                        revStateBuffer,
                        out revStateHandle
                    );
                }
                finally
                {
                    AnonCredsHelpers.FreeByteBuffer(revStateBuffer);
                }
                if (result != ErrorCode.Success)
                    throw new AnonCredsException(result, AnonCredsHelpers.GetCurrentError());
            }

            ffiEntries[i] = new FfiCredentialEntry
            {
                Credential = credHandle,
                Timestamp = entry.Timestamp ?? -1,
                RevState = revStateHandle,
            };
        }
        var ptr = Marshal.AllocHGlobal(ffiEntries.Length * Marshal.SizeOf<FfiCredentialEntry>());
        for (var i = 0; i < ffiEntries.Length; i++)
        {
            Marshal.StructureToPtr(
                ffiEntries[i],
                ptr + i * Marshal.SizeOf<FfiCredentialEntry>(),
                false
            );
        }
        return new FfiCredentialEntryList { Data = ptr, Count = (nuint)ffiEntries.Length };
    }

    private static FfiCredentialProveList CreateCredentialsProveList(
        string presReqJson,
        string? selfAttestJson,
        string? credentialsJson
    )
    {
        var proveList = new List<FfiCredentialProve>();
        // Optional: referents mapping supplied with credentials
        Dictionary<string, int> referentToEntryIdx = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(credentialsJson))
        {
            try
            {
                var entries = JsonSerializer.Deserialize<CredentialEntryJson[]>(credentialsJson);
                if (entries != null)
                {
                    for (int i = 0; i < entries.Length; i++)
                    {
                        var refs = entries[i].Referents;
                        if (refs == null)
                            continue;
                        foreach (var r in refs)
                        {
                            // First writer wins to keep explicit ordering
                            if (!referentToEntryIdx.ContainsKey(r))
                                referentToEntryIdx[r] = i;
                        }
                    }
                }
            }
            catch
            {
                // ignore malformed mapping; fall back to default mapping
            }
        }

        // Build a set of referents that are satisfied via self-attested values
        HashSet<string> selfAttestedReferents = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            try
            {
                var map =
                    JsonSerializer.Deserialize<Dictionary<string, string>>(selfAttestJson!)
                    ?? new();
                foreach (var k in map.Keys)
                {
                    selfAttestedReferents.Add(k);
                }
            }
            catch
            {
                // ignore malformed self-attested JSON; treat as none
            }
        }

        using (var doc = JsonDocument.Parse(presReqJson))
        {
            var root = doc.RootElement;

            if (root.TryGetProperty("requested_attributes", out var requestedAttributes))
            {
                foreach (var attr in requestedAttributes.EnumerateObject())
                {
                    var referent = attr.Name;
                    // Skip if this referent is self-attested
                    if (selfAttestedReferents.Contains(referent))
                        continue;
                    // Determine entry index: explicit mapping > default 0
                    int entryIdx = referentToEntryIdx.TryGetValue(referent, out var idx) ? idx : 0;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = entryIdx,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 0,
                            Reveal = 1,
                        }
                    );
                }
            }

            if (root.TryGetProperty("requested_predicates", out var requestedPredicates))
            {
                foreach (var pred in requestedPredicates.EnumerateObject())
                {
                    var referent = pred.Name;
                    int entryIdx = referentToEntryIdx.TryGetValue(referent, out var idx) ? idx : 0;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = entryIdx,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 1,
                            Reveal = 0,
                        }
                    );
                }
            }
        }

        if (proveList.Count == 0)
        {
            return new FfiCredentialProveList { Data = IntPtr.Zero, Count = 0 };
        }

        var proveArray = proveList.ToArray();
        var size = Marshal.SizeOf<FfiCredentialProve>();
        var ptr = Marshal.AllocHGlobal(size * proveArray.Length);

        for (int i = 0; i < proveArray.Length; i++)
        {
            Marshal.StructureToPtr(proveArray[i], ptr + (i * size), false);
        }

        return new FfiCredentialProveList { Data = ptr, Count = (nuint)proveArray.Length };
    }

    private class CredentialEntryJson
    {
        [JsonPropertyName("credential")]
        public string Credential { get; set; } = "";

        [JsonPropertyName("timestamp")]
        public int? Timestamp { get; set; }

        [JsonPropertyName("rev_state")]
        public string? RevState { get; set; }

        [JsonPropertyName("referents")]
        public List<string>? Referents { get; set; }
    }
}
