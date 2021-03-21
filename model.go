package mispfeedgenerator

type attribute struct {
	_fieldsForFeed     []string `json:"-"`
	_hash              string   `json:"-"`
	Value              string   `json:"value"`
	StrTimestamp       string   `json:"timestamp"`
	Comment            string   `json:"comment"`
	Category           string   `json:"category"`
	UUID               string   `json:"uuid"`
	Type               string   `json:"type"`
	ToIds              bool     `json:"to_ids"`
	Deleted            bool     `json:"deleted"`
	DisableCorrelation bool     `json:"disable_correlation"`
}

type orgc struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type eventManifest struct {
	Orgc          orgc   `json:"Orgc"`
	Tag           []tag  `json:"Tag"`
	Info          string `json:"info"`
	Date          string `json:"date"`
	Analysis      int    `json:"analysis"`
	ThreatLevelID int    `json:"threat_level_id"`
	StrTimestamp  string `json:"timestamp"`
}

type tag struct {
	Name   string `json:"name"`
	Colour string `json:"colour"`
}

// Event definition
type event struct {
	_fieldsForFeed  []string               `json:"-"`
	_manifest       map[string]interface{} `json:"-"`
	_hashes         []string               `json:"-"`
	_attributeTypes attributeTypes         `json:"-"`
	StrTimestamp    string                 `json:"timestamp"`
	ExtendsUUID     string                 `json:"extends_uuid"`
	Info            string                 `json:"info"`
	Date            string                 `json:"date"`
	UUID            string                 `json:"uuid"`
	// Analysis: 0 means initial, 1 ongoing, 2 completed
	Analysis         int         `json:"analysis"`
	PublishTimestamp string      `json:"publish_timestamp"`
	Published        bool        `json:"published"`
	ThreatLevelID    int         `json:"threat_level_id"`
	Orgc             orgc        `json:"Orgc"`
	Tag              []tag       `json:"Tag"`
	Attribute        []attribute `json:"Attribute"`
	Object           []struct {
		StrTimestamp    string `json:"timestamp"`
		SharingGroupID  string `json:"sharing_group_id"`
		Description     string `json:"description"`
		Name            string `json:"name"`
		Comment         string `json:"comment"`
		UUID            string `json:"uuid"`
		TemplateVersion string `json:"template_version"`
		Distribution    string `json:"distribution"`
		Deleted         bool   `json:"deleted"`
		TemplateUUID    string `json:"template_uuid"`
		MetaCategory    string `json:"meta-category"`
		ObjectReference []struct {
			Timestamp        string `json:"timestamp"`
			RelationshipType string `json:"relationship_type"`
			ObjectUUID       string `json:"object_uuid"`
			Comment          string `json:"comment"`
			UUID             string `json:"uuid"`
			ReferencedUUID   string `json:"referenced_uuid"`
		} `json:"ObjectReference,omitempty"`
		Attribute []struct {
			Value              string `json:"value"`
			StrTimestamp       string `json:"timestamp"`
			Comment            string `json:"comment"`
			Category           string `json:"category"`
			UUID               string `json:"uuid"`
			ObjectRelation     string `json:"object_relation"`
			Type               string `json:"type"`
			ToIds              bool   `json:"to_ids"`
			Deleted            bool   `json:"deleted"`
			DisableCorrelation bool   `json:"disable_correlation"`
		} `json:"Attribute"`
	} `json:"Object"`
}

type eventFeed struct {
	Event event `json:"Event"`
}

type attributeTypes struct {
	Result struct {
		Categories           []string `json:"categories"`
		CategoryTypeMappings struct {
			AntivirusDetection   []string `json:"Antivirus detection"`
			ArtifactsDropped     []string `json:"Artifacts dropped"`
			Attribution          []string `json:"Attribution"`
			ExternalAnalysis     []string `json:"External analysis"`
			FinancialFraud       []string `json:"Financial fraud"`
			InternalReference    []string `json:"Internal reference"`
			NetworkActivity      []string `json:"Network activity"`
			Other                []string `json:"Other"`
			PayloadDelivery      []string `json:"Payload delivery"`
			PayloadInstallation  []string `json:"Payload installation"`
			PayloadType          []string `json:"Payload type"`
			PersistenceMechanism []string `json:"Persistence mechanism"`
			Person               []string `json:"Person"`
			SocialNetwork        []string `json:"Social network"`
			SupportTool          []string `json:"Support Tool"`
			TargetingData        []string `json:"Targeting data"`
		} `json:"category_type_mappings"`
		SaneDefaults struct {
			As struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"AS"`
			AbaRtn struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"aba-rtn"`
			Anonymised struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"anonymised"`
			Attachment struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"attachment"`
			Authentihash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"authentihash"`
			BankAccountNr struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"bank-account-nr"`
			Bic struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"bic"`
			Bin struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"bin"`
			Boolean struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"boolean"`
			Bro struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"bro"`
			Btc struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"btc"`
			CampaignID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"campaign-id"`
			CampaignName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"campaign-name"`
			CcNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"cc-number"`
			Cdhash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"cdhash"`
			ChromeExtensionID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"chrome-extension-id"`
			Comment struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"comment"`
			CommunityID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"community-id"`
			Cookie struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"cookie"`
			Cortex struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"cortex"`
			Counter struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"counter"`
			CountryOfResidence struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"country-of-residence"`
			Cpe struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"cpe"`
			Dash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"dash"`
			DateOfBirth struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"date-of-birth"`
			Datetime struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"datetime"`
			Dkim struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"dkim"`
			DkimSignature struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"dkim-signature"`
			DNSSoaEmail struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"dns-soa-email"`
			Domain struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"domain"`
			DomainIP struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"domain|ip"`
			Email struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email"`
			EmailAttachment struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-attachment"`
			EmailBody struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-body"`
			EmailDst struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-dst"`
			EmailDstDisplayName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-dst-display-name"`
			EmailHeader struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-header"`
			EmailMessageID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-message-id"`
			EmailMimeBoundary struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-mime-boundary"`
			EmailReplyTo struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-reply-to"`
			EmailSrc struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-src"`
			EmailSrcDisplayName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-src-display-name"`
			EmailSubject struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-subject"`
			EmailThreadIndex struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-thread-index"`
			EmailXMailer struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"email-x-mailer"`
			Eppn struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"eppn"`
			FaviconMmh3 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"favicon-mmh3"`
			Filename struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename"`
			FilenameAuthentihash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|authentihash"`
			FilenameImpfuzzy struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|impfuzzy"`
			FilenameImphash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|imphash"`
			FilenameMd5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|md5"`
			FilenamePehash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|pehash"`
			FilenameSha1 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha1"`
			FilenameSha224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha224"`
			FilenameSha256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha256"`
			FilenameSha3224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha3-224"`
			FilenameSha3256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha3-256"`
			FilenameSha3384 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha3-384"`
			FilenameSha3512 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha3-512"`
			FilenameSha384 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha384"`
			FilenameSha512 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha512"`
			FilenameSha512224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha512/224"`
			FilenameSha512256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|sha512/256"`
			FilenameSsdeep struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|ssdeep"`
			FilenameTlsh struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|tlsh"`
			FilenameVhash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"filename|vhash"`
			FirstName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"first-name"`
			Float struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"float"`
			FrequentFlyerNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"frequent-flyer-number"`
			FullName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"full-name"`
			Gender struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"gender"`
			Gene struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"gene"`
			GitCommitID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"git-commit-id"`
			GithubOrganisation struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"github-organisation"`
			GithubRepository struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"github-repository"`
			GithubUsername struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"github-username"`
			HasshMd5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"hassh-md5"`
			HasshserverMd5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"hasshserver-md5"`
			Hex struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"hex"`
			Hostname struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"hostname"`
			HostnamePort struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"hostname|port"`
			HTTPMethod struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"http-method"`
			Iban struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"iban"`
			IdentityCardNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"identity-card-number"`
			Impfuzzy struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"impfuzzy"`
			Imphash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"imphash"`
			IPDst struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ip-dst"`
			IPDstPort struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ip-dst|port"`
			IPSrc struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ip-src"`
			IPSrcPort struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ip-src|port"`
			IssueDateOfTheVisa struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"issue-date-of-the-visa"`
			Ja3FingerprintMd5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ja3-fingerprint-md5"`
			JabberID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"jabber-id"`
			JarmFingerprint struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"jarm-fingerprint"`
			KustoQuery struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"kusto-query"`
			LastName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"last-name"`
			Link struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"link"`
			MacAddress struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"mac-address"`
			MacEui64 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"mac-eui-64"`
			MalwareSample struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"malware-sample"`
			MalwareType struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"malware-type"`
			Md5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"md5"`
			MiddleName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"middle-name"`
			MimeType struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"mime-type"`
			MobileApplicationID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"mobile-application-id"`
			Mutex struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"mutex"`
			NamedPipe struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"named pipe"`
			Nationality struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"nationality"`
			Other struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"other"`
			PassengerNameRecordLocatorNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"passenger-name-record-locator-number"`
			PassportCountry struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"passport-country"`
			PassportExpiration struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"passport-expiration"`
			PassportNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"passport-number"`
			PatternFilename struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pattern-filename"`
			PatternInFile struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pattern-in-file"`
			PatternInMemory struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pattern-in-memory"`
			PatternInTraffic struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pattern-in-traffic"`
			PaymentDetails struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"payment-details"`
			Pdb struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pdb"`
			Pehash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pehash"`
			PgpPrivateKey struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pgp-private-key"`
			PgpPublicKey struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"pgp-public-key"`
			PhoneNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"phone-number"`
			PlaceOfBirth struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"place-of-birth"`
			PlacePortOfClearance struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"place-port-of-clearance"`
			PlacePortOfOnwardForeignDestination struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"place-port-of-onward-foreign-destination"`
			PlacePortOfOriginalEmbarkation struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"place-port-of-original-embarkation"`
			Port struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"port"`
			PrimaryResidence struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"primary-residence"`
			ProcessState struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"process-state"`
			Prtn struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"prtn"`
			RedressNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"redress-number"`
			Regkey struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"regkey"`
			RegkeyValue struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"regkey|value"`
			Sha1 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha1"`
			Sha224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha224"`
			Sha256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha256"`
			Sha3224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha3-224"`
			Sha3256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha3-256"`
			Sha3384 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha3-384"`
			Sha3512 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha3-512"`
			Sha384 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha384"`
			Sha512 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha512"`
			Sha512224 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha512/224"`
			Sha512256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sha512/256"`
			Sigma struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"sigma"`
			SizeInBytes struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"size-in-bytes"`
			Snort struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"snort"`
			SpecialServiceRequest struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"special-service-request"`
			Ssdeep struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"ssdeep"`
			Stix2Pattern struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"stix2-pattern"`
			TargetEmail struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-email"`
			TargetExternal struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-external"`
			TargetLocation struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-location"`
			TargetMachine struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-machine"`
			TargetOrg struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-org"`
			TargetUser struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"target-user"`
			Telfhash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"telfhash"`
			Text struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"text"`
			ThreatActor struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"threat-actor"`
			Tlsh struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"tlsh"`
			TravelDetails struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"travel-details"`
			TwitterID struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"twitter-id"`
			URI struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"uri"`
			URL struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"url"`
			UserAgent struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"user-agent"`
			Vhash struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"vhash"`
			VisaNumber struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"visa-number"`
			Vulnerability struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"vulnerability"`
			Weakness struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"weakness"`
			WhoisCreationDate struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-creation-date"`
			WhoisRegistrantEmail struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-registrant-email"`
			WhoisRegistrantName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-registrant-name"`
			WhoisRegistrantOrg struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-registrant-org"`
			WhoisRegistrantPhone struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-registrant-phone"`
			WhoisRegistrar struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"whois-registrar"`
			WindowsScheduledTask struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"windows-scheduled-task"`
			WindowsServiceDisplayname struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"windows-service-displayname"`
			WindowsServiceName struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"windows-service-name"`
			X509FingerprintMd5 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"x509-fingerprint-md5"`
			X509FingerprintSha1 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"x509-fingerprint-sha1"`
			X509FingerprintSha256 struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"x509-fingerprint-sha256"`
			Xmr struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"xmr"`
			Yara struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"yara"`
			Zeek struct {
				DefaultCategory string `json:"default_category"`
				ToIds           int    `json:"to_ids"`
			} `json:"zeek"`
		} `json:"sane_defaults"`
		Types []string `json:"types"`
	} `json:"result"`
}
