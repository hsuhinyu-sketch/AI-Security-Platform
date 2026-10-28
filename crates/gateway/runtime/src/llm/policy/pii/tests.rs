use super::super::{Action, Builtin, Policy, RegexResult, RegexRule, RegexRules};

fn rules(action: Action, builtin: Builtin) -> RegexRules {
	RegexRules {
		action,
		rules: vec![RegexRule::Builtin { builtin }],
	}
}

#[test]
fn builtin_rejection_and_masking_preserve_unicode_offsets_and_overlapping_matches() {
	for (builtin, input, expected) in [
		(
			Builtin::Email,
			"邮箱 alice@example.com / bob@example.org",
			"邮箱 <EMAIL_ADDRESS> / <EMAIL_ADDRESS>",
		),
		(
			Builtin::Ssn,
			"证件 123-45-6789 / 123456789",
			"证件 <SSN> / <SSN>",
		),
		(
			Builtin::CreditCard,
			"卡号 4111 1111 1111 1111",
			"卡号 <CREDIT_CARD>",
		),
		(
			Builtin::CaSin,
			"号码 046 454 286 / 046454286",
			"号码 <CA_SIN> / <CA_SIN>",
		),
		(
			Builtin::PhoneNumber,
			"电话 +1 (650) 253-0000",
			"电话 <PHONE_NUMBER>",
		),
	] {
		assert!(matches!(
			Policy::apply_prompt_guard_regex(input, &rules(Action::Reject, builtin.clone())),
			Some(RegexResult::Reject)
		));
		let Some(RegexResult::Mask(masked)) =
			Policy::apply_prompt_guard_regex(input, &rules(Action::Mask, builtin))
		else {
			panic!("expected a masked value for {input}");
		};
		assert_eq!(masked, expected);
	}
}

#[test]
fn builtin_rules_leave_clean_text_unchanged() {
	for builtin in [
		Builtin::Email,
		Builtin::Ssn,
		Builtin::CreditCard,
		Builtin::CaSin,
		Builtin::PhoneNumber,
	] {
		for action in [Action::Reject, Action::Mask] {
			assert!(
				Policy::apply_prompt_guard_regex("仅有正常文字", &rules(action, builtin.clone())).is_none()
			);
		}
	}
}

#[test]
fn multiple_builtin_rules_apply_to_the_previously_masked_text() {
	let rules = RegexRules {
		action: Action::Mask,
		rules: vec![
			RegexRule::Builtin {
				builtin: Builtin::Email,
			},
			RegexRule::Builtin {
				builtin: Builtin::PhoneNumber,
			},
		],
	};
	let Some(RegexResult::Mask(masked)) =
		Policy::apply_prompt_guard_regex("联系 alice@example.com, +1 (650) 253-0000", &rules)
	else {
		panic!("expected both builtins to mask");
	};
	assert_eq!(masked, "联系 <EMAIL_ADDRESS>, <PHONE_NUMBER>");
}
