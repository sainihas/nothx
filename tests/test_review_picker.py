from types import SimpleNamespace
from unittest.mock import patch

import pytest

from nothx.cli import _is_marketing_candidate, _review_scan_decisions, _show_details
from nothx.models import Action, Classification, EmailType, SenderStats


def row(
    index=0,
    *,
    account="owner@example.com",
    email_type=EmailType.MARKETING,
    action=Action.REVIEW,
    source="ai",
    list_id=None,
):
    sender = SenderStats(
        domain="mail.example",
        account_key=account,
        identity_kind="list_id" if list_id else "from",
        identity_value=list_id or f"person-{index}@mail.example",
        total_emails=5,
        seen_emails=0,
        has_unsubscribe=True,
        sample_senders=[f"person-{index}@mail.example"],
        sample_subjects=["Weekend sale"],
        list_id=list_id,
    )
    return (
        sender.classification_key,
        sender,
        Classification(email_type, action, 0.9, "Synthetic reason", source),
    )


def run_picker(groups, answers, searches=(), **kwargs):
    prompts = []
    values = iter(answers)

    def select(message, **kwargs):
        prompts.append((message, kwargs))
        return SimpleNamespace(ask=lambda: next(values))

    with (
        patch("nothx.cli.questionary.select", side_effect=select),
        patch("nothx.cli.questionary.text") as text,
    ):
        text.return_value.ask.side_effect = list(searches)
        _review_scan_decisions(*groups, **kwargs)
    return prompts


def test_personal_kept_senders_are_not_offered_and_finish_does_not_walk_them():
    kept = [row(i, email_type=EmailType.UNKNOWN, action=Action.KEEP) for i in range(1400)]
    for _, sender, _ in kept:
        sender.has_unsubscribe = False
        sender.sample_subjects = ["Dinner tomorrow"]
    prompts = run_picker(([], kept, [], []), ["finish"])
    assert len(prompts) == 1
    assert [choice.value for choice in prompts[0][1]["choices"]] == ["finish"]
    assert len(kept) == 1400


def test_account_sender_and_list_stay_distinct_when_editing_one():
    rows = [
        row(0, account="one@example.com"),
        row(1, account="one@example.com"),
        row(0, account="two@example.com"),
        row(0, list_id="news.one.example"),
        row(0, list_id="news.two.example"),
    ]
    review = rows[:]
    blocked = []
    selected = rows[1]
    prompts = run_picker(
        ([], [], review, blocked), ["review", f"sender:{selected[0]}", "block", "finish"]
    )
    labels = [
        choice.title
        for choice in prompts[1][1]["choices"]
        if str(choice.value).startswith("sender:")
    ]
    assert len(set(labels)) == 5
    assert all("@" in label for label in labels)
    assert "person-1@mail.example" in labels[1]
    assert "one@example.com" in labels[1]
    assert "news.one.example" in labels[3]
    assert "person-0@mail.example" in labels[3]
    assert len(review) == 4 and blocked[0][0] == selected[0]
    assert blocked[0][2].source == "user_rule"


def test_search_and_pages_are_bounded_and_finish_is_always_available():
    review = [row(i) for i in range(100)]
    prompts = run_picker(
        ([], [], review, []), ["review", "next", "search", "finish"], ["person-73@"]
    )
    assert len([c for c in prompts[1][1]["choices"] if str(c.value).startswith("sender:")]) == 20
    assert len([c for c in prompts[2][1]["choices"] if str(c.value).startswith("sender:")]) == 20
    matches = [c for c in prompts[3][1]["choices"] if str(c.value).startswith("sender:")]
    assert len(matches) == 1 and "person-73@" in matches[0].title
    assert all(any(c.value == "finish" for c in opts["choices"]) for _, opts in prompts)
    assert len(review) == 100


def test_cancel_preserves_prior_changes_without_changing_unvisited_senders():
    review = [row(i) for i in range(3)]
    keys = [item[0] for item in review]
    kept = []
    run_picker(
        ([], kept, review, []), ["review", f"sender:{keys[0]}", "keep", f"sender:{keys[1]}", None]
    )
    assert [item[0] for item in kept] == [keys[0]]
    assert [item[0] for item in review] == keys[1:]


@pytest.mark.parametrize("source,protected", [("scan_policy", 0), ("transactional_policy", 1)])
def test_incomplete_or_mixed_protected_sender_offers_no_destructive_action(source, protected):
    item = row(source=source)
    item[1].protected_subject_emails = protected
    with patch("nothx.cli._confirmed_provider_threat", return_value=False):
        prompts = run_picker(
            ([], [], [item], []), ["review", f"sender:{item[0]}", "unchanged", "finish"]
        )
    actions = {c.value for c in prompts[2][1]["choices"]}
    assert not actions & {"block", "unsub"}


@pytest.mark.parametrize("email_type", [EmailType.TRANSACTIONAL, EmailType.SECURITY])
def test_receipts_security_and_personal_threads_are_not_marketing(email_type):
    _, sender, classification = row(email_type=email_type)
    assert not _is_marketing_candidate(sender, classification)
    classification.email_type = EmailType.UNKNOWN
    sender.sample_subjects = ["Re: Dinner tomorrow"]
    sender.list_id = "group.discussion.example"
    assert not _is_marketing_candidate(sender, classification)


def test_details_do_not_show_personal_kept_sender(capsys):
    kept = row(email_type=EmailType.UNKNOWN, action=Action.KEEP)
    kept[1].sample_subjects = ["Dinner tomorrow"]
    _show_details([], [kept], [], [])
    assert "person-0@" not in capsys.readouterr().out


def test_incomplete_scan_stays_immutable_after_keep_and_reopen():
    item = row(source="scan_policy")
    review = [item]
    kept = []
    prompts = run_picker(
        ([], kept, review, []),
        [
            "review",
            f"sender:{item[0]}",
            "keep",
            "back",
            "keep",
            f"sender:{item[0]}",
            "unchanged",
            "finish",
        ],
        incomplete_accounts=frozenset({"owner@example.com"}),
    )
    action_prompts = [opts for message, opts in prompts if message.startswith("Action for")]
    assert len(action_prompts) == 2
    assert all(
        not {c.value for c in opts["choices"]} & {"block", "unsub"} for opts in action_prompts
    )
    assert kept[0][2].source == "user_rule"


def test_saved_review_search_pages_and_finish_do_not_visit_every_sender():
    from nothx.cli import _pick_saved_reviews

    rows = [(str(i), f"owner@example.com · sender-{i}@mail.example") for i in range(1400)]
    with (
        patch("nothx.cli.questionary.select") as select,
        patch("nothx.cli.questionary.text") as search,
    ):
        select.return_value.ask.side_effect = ["next", "search", "row:731", "finish"]
        search.return_value.ask.return_value = "sender-731@"
        assert list(_pick_saved_reviews(rows)) == ["731"]
    prompts = select.call_args_list
    assert len([c for c in prompts[0].kwargs["choices"] if c.value.startswith("row:")]) == 20
    assert len([c for c in prompts[1].kwargs["choices"] if c.value.startswith("row:")]) == 20
    assert [c.value for c in prompts[2].kwargs["choices"] if c.value.startswith("row:")] == [
        "row:731"
    ]
    assert all(p.kwargs["default"] == "finish" for p in prompts)
    assert len(rows) == 1400
