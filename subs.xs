#define PERL_NO_GET_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define ENTERSUB_COMMON_DECLARATIONS   \
    dVAR; dSP; dPOPss;          \
    PERL_CONTEXT *cx;           \
    I32 gimme                   \

#define ENTERSUB_COMMON_END STMT_START {                        \
    SAVETMPS;                                                   \
    if ((cx->blk_u16 & OPpENTERSUB_LVAL_MASK) == OPpLVAL_INTRO) \
        DIE(aTHX_ "Can't modify non-lvalue subroutine call");   \
    RETURNOP(CvSTART(cv));                                      \
} STMT_END

#define ENTERSUB_COMMON_BODY \
    PADLIST * const padlist = CvPADLIST(cv); \
    PUSHBLOCK(cx, CXt_SUB, MARK); \
    PUSHSUB(cx); \
    cx->blk_sub.retop = PL_op->op_next; \
    CvDEPTH(cv)++; \
    if (CvDEPTH(cv) >= 2) { \
        PERL_STACK_OVERFLOW_CHECK(); \
        Perl_pad_push(aTHX_ padlist, CvDEPTH(cv)); \
    } \
    SAVECOMPPAD(); \
    PAD_SET_CUR_NOSAVE(padlist, CvDEPTH(cv))


#define ENTERSUB_COMMON_ARGS    STMT_START {                    \
    AV *const av = MUTABLE_AV(PAD_SVl(0));                      \
    if (AvREAL(av)) {                                           \
        /* @_ is normally not REAL--this should only ever       \
         * happen when DB::sub() calls things that modify @_ */ \
        av_clear(av);                                           \
        AvREAL_off(av);                                         \
        AvREIFY_on(av);                                         \
    }                                                           \
    cx->blk_sub.savearray = GvAV(PL_defgv);                     \
    GvAV(PL_defgv) = MUTABLE_AV(SvREFCNT_inc_simple(av));       \
    CX_CURPAD_SAVE(cx->blk_sub);                                \
    cx->blk_sub.argarray = av;                                  \
    ++MARK;                                                     \
                                                                \
    if (items - 1 > AvMAX(av)) {                                \
        SV **ary = AvALLOC(av);                                 \
        AvMAX(av) = items - 1;                                  \
        Renew(ary, items, SV*);                                 \
        AvALLOC(av) = ary;                                      \
        AvARRAY(av) = ary;                                      \
    }                                                           \
                                                                \
    Copy(MARK,AvARRAY(av),items,SV*);                           \
    AvFILLp(av) = items - 1;                                    \
                                                                \
    MARK = AvARRAY(av);                                         \
    while (items--) {                                           \
        if (*MARK) {                                            \
            if (SvPADTMP(*MARK) && !IS_PADGV(*MARK)) {          \
                *MARK = sv_mortalcopy(*MARK);                   \
            }                                                   \
            SvTEMP_off(*MARK);                                  \
        }                                                       \
        MARK++;                                                 \
    }                                                           \
} STMT_END


/* $foo->() */
STATIC OP*
S_pp_entersubpadsv_args(pTHX)
{
    ENTERSUB_COMMON_DECLARATIONS;
    CV *cv;
    GV *gv;
    const bool hasargs = TRUE;

    if (!sv)
        DIE(aTHX_ "Not a CODE reference");

    switch (SvTYPE(sv)) {
    /* This is overwhelming the most common case:  */
    case SVt_PVGV:
      we_have_a_glob:
    if (!(cv = GvCVu((const GV *)sv))) {
        HV *stash;
        cv = sv_2cv(sv, &stash, &gv, 0);
    }
    if (!cv) {
        ENTER;
        SAVETMPS;
        DIE(aTHX_ "nope");
        //goto try_autoload;
    }
    break;
    case SVt_PVLV:
        if(isGV_with_GP(sv)) goto we_have_a_glob;
    /*FALLTHROUGH*/
    default:
        if (sv == &PL_sv_yes) {		/* unfound import, ignore */
            if (hasargs)
            SP = PL_stack_base + POPMARK;
            else
            (void)POPMARK;
            RETURN;
        }
        SvGETMAGIC(sv);
        if (SvROK(sv)) {
            if (SvAMAGIC(sv)) {
            sv = amagic_deref_call(sv, to_cv_amg);
            /* Don't SPAGAIN here.  */
            }
        }
        else {
            const char *sym;
            STRLEN len;
            if (!SvOK(sv))
                DIE(aTHX_ PL_no_usym, "a subroutine");
            sym = SvPV_nomg_const(sv, len);
            if (PL_op->op_private & HINT_STRICT_REFS)
                DIE(aTHX_ "Can't use string (\"%" SVf32 "\"%s) as a subroutine ref while \"strict refs\" in use", sv, len>32 ? "..." : "");
            cv = get_cvn_flags(sym, len, GV_ADD|SvUTF8(sv));
            break;
        }
        cv = MUTABLE_CV(SvRV(sv));
        if (SvTYPE(cv) == SVt_PVCV)
            break;
        /* FALL THROUGH */
    case SVt_PVHV:
    case SVt_PVAV:
        DIE(aTHX_ "Not a CODE reference");
        /* This is the second most common case:  */
    case SVt_PVCV:
        cv = MUTABLE_CV(sv);
        break;
    }

    
    ENTER;

    gimme = GIMME_V;

    dMARK;
    SSize_t items = SP - MARK;

    ENTERSUB_COMMON_BODY;

    /* Handle arguments */
    ENTERSUB_COMMON_ARGS;

    ENTERSUB_COMMON_END;
}

/* $foo->() */
STATIC OP*
S_pp_entersubpadsv_noargs(pTHX)
{
    ENTERSUB_COMMON_DECLARATIONS;
    CV *cv;
    const bool hasargs = TRUE;
    
    sv_dump(sv);
    exit(1);
     //= MUTABLE_CV(sv)
    
    ENTER;

    gimme = GIMME_V;

    dMARK;
    SSize_t items = SP - MARK;

    ENTERSUB_COMMON_BODY;

    ENTERSUB_COMMON_END;
}

/* foo() */
STATIC OP*
S_pp_entersubcv_args(pTHX)
{
    ENTERSUB_COMMON_DECLARATIONS;
    CV *cv = MUTABLE_CV(sv);
    const bool hasargs = TRUE;
    
    ENTER;

    gimme = GIMME_V;

    dMARK;
    SSize_t items = SP - MARK;

    ENTERSUB_COMMON_BODY;

    /* Handle arguments */
    ENTERSUB_COMMON_ARGS;

    ENTERSUB_COMMON_END;
}

/* &foo */
STATIC OP*
S_pp_entersubcv_noargs(pTHX)
{
    ENTERSUB_COMMON_DECLARATIONS;
    CV *cv = MUTABLE_CV(sv);
    const bool hasargs = FALSE;

    ENTER;

    gimme = GIMME_V;

    dMARK;

    ENTERSUB_COMMON_BODY;
    
    ENTERSUB_COMMON_END;
}

static I32 count = 0;
static I32 total = 0;

STATIC OP*
THX_find_entersub_last_op(pTHX_ OP* entersubop)
#define find_entersub_last_op(o) THX_find_entersub_last_op(aTHX_ o)
{
    OP *aop = cUNOPx(entersubop)->op_first;
    if (!aop->op_sibling)
       aop = cUNOPx(aop)->op_first;

    /* We want the last sibling */
    for (aop = aop->op_sibling; aop->op_sibling; aop = aop->op_sibling) { }

    while ( aop && aop->op_type == OP_NULL ) {
        aop = cUNOPx(aop)->op_first;
    }

    return aop;
}

STATIC void
optimize_entersub(pTHX_ OP *entersubop, AV * const comppad_name)
#define optimize_entersub(o, av) optimize_entersub(aTHX_ o, av)
{
    OP * aop = find_entersub_last_op(entersubop);
    OP * gvop;
    CV * cv;
    HV * stash;


    if (!aop) {
        return;
    }

    /* XXX Does removing the refgen cause any freeing issues..? */
    if ( aop->op_type == OP_REFGEN ) { /* sub {...}->() */
        /* We can throw away the refgen and replace the entersub with a cv variant */
        OP *push = cUNOPx(cUNOPx(aop)->op_first)->op_first;
        if ( push->op_type == OP_PUSHMARK && push->op_sibling->op_type == OP_ANONCODE ) {
            const bool hasargs = (entersubop->op_flags & OPf_STACKED) != 0;

            /* Bye, refgen! */
            op_null(aop);

            entersubop->op_ppaddr = hasargs
                                  ? S_pp_entersubcv_args
                                  : S_pp_entersubcv_noargs;
            count++;
            return;
        }
    }


    /* This while handles both *foo->() and foo() when the rv2cv has been optimized away
     * as an OP_GV
     */
    OP * orig_aop = aop;
    while ( aop && (aop->op_type == OP_NULL || aop->op_type == OP_RV2GV) ) {
        aop = cUNOPx(aop)->op_first;
        /* do { "foo" }->() and *{"foo"}->() */
        if ( aop->op_type == OP_SCOPE ) {
            OP * inner = cUNOPx(aop)->op_first->op_sibling;
            
            if ( inner->op_type == OP_CONST ) { /* *{"foo"}->() and &{"foo"} */
                SV * sv = cSVOPx(inner)->op_sv;
                if ( sv && sv != &PL_sv_undef && SvOK(sv) ) {
                    STRLEN len;
                    const char *sym = SvPV_nomg_const(sv, len);
                    if (entersubop->op_private & HINT_STRICT_REFS) {
                        croak("Can't use string (\"%" SVf32 "\"%s) as a subroutine ref while \"strict refs\" in use", sv, len>32 ? "..." : "");
                    }
                    cv = get_cvn_flags(sym, len, GV_ADD|SvUTF8(sv));
                    if ( !CvLVALUE(cv) ) {
                        goto got_cv;
                    }
                }
            }
            else { /* This can catch cases like *{ *foo }->() */
                aop = inner;
            }
        }
    }
    
    if ( !aop ) {
        return;
    }

    gvop = aop;

    switch ( aop->op_type ) {
        case OP_GELEM:  /* *foo{CODE}->() */
        {
            OP *constop;
            SV *sv = NULL;
            
            gvop = cUNOPx(aop)->op_first;
            constop = gvop->op_sibling;

            while ( gvop && (gvop->op_type == OP_NULL || gvop->op_type == OP_RV2GV) ) {
                gvop = cUNOPx(gvop)->op_first;
            }
            
            if (!gvop || gvop->op_type != OP_GV || constop->op_type != OP_CONST ) {
               break;
            }
            
            sv = cSVOPx_sv(constop);
            if ( !sv || sv == &PL_sv_undef ) {
                break;
            }
            else {
                STRLEN len;
                const char * const elem = SvPV_const(sv, len);
            
                if ( !elem || len != 4 || !strEQ(elem, "CODE") ) {
                    break;
                }
            }
            /* fallthrough */
        }
        case OP_GV: /* foo() */
        {
            GV *gv = cGVOPx_gv(gvop);

            if (isGV(gv) && (cv = GvCV(gv)) && !CvLVALUE(cv)) {
                got_cv:
                if ( !CvISXSUB(cv) && (!CvROOT(cv) || !CvPADLIST(cv)) ) {
                    /* XXX Predeclared subs used before their definition, as well
                     * as autoloaded subs
                     */
                    break;
                }
                
                {
                    GV *cvgv = CvGV(cv);
                    if ( GvNAMELEN(cvgv) == 8 && strEQ(GvNAME(cvgv), "AUTOLOAD") ) {
                        break;
                    }
                }
                
                SV *maybe_const;
                if ( CvCONST(cv) && (maybe_const = cv_const_sv(cv)) ) {
                    OP *new_op = newSVOP(OP_CONST, 0, SvREFCNT_inc_simple_NN(maybe_const));

                    new_op->op_next = entersubop;
                    op_null(entersubop);
                    entersubop->op_next = new_op;
                    cUNOPx(entersubop)->op_first = entersubop->op_next;

                    return;
                }
                
                op_null(orig_aop);
                orig_aop->op_next = (OP*)newSVOP(OP_CONST, 0, (SV*)cv);
                cUNOPx(orig_aop)->op_first = orig_aop->op_next; 
                orig_aop->op_next->op_next = entersubop;
                entersubop->op_type   = OP_ENTERSUB;

                /* Prevent anything from freeing this CV */
                /* XXX This should probably only happen once? */
                SvREFCNT_inc(cv);

                if (CvISXSUB(cv)) {
                    /* entersubop->op_ppaddr = S_pp_entersubxscv;
                     * For now, let entersub handle xsubs
                     */
                }
                else {
                    const bool hasargs = (entersubop->op_flags & OPf_STACKED) != 0;

                    entersubop->op_ppaddr = hasargs
                                          ? S_pp_entersubcv_args
                                          : S_pp_entersubcv_noargs;
                    count++;
                }
            }
            break;
        }
        /*
        case OP_PADSV: { //$foo->()
            const bool hasargs = (entersubop->op_flags & OPf_STACKED) != 0;

            entersubop->op_ppaddr = hasargs
                                  ? S_pp_entersubpadsv_args
                                  : S_pp_entersubpadsv_noargs;
            break;
        }
        */
        default: /* $foo->baz(), $foo[0]->(), $foo{bar}->(), $foo->$bar() */
            break;
    }
    return;
}

void
doof(pTHX_)
{
    PerlIO_printf(Perl_debug_log, "Total: %d. Optimized: %d.\n", total, count);
}

static OP *(*nxck_entersubop)(pTHX_ OP *o);
static OP *(*nxck_exists)(pTHX_ OP *o);
static OP *(*nxck_defined)(pTHX_ OP *o);

/* XXX TODO sub foo {} defined &foo; can be optimized out */

/* Damn silly. exists(&foo) doesn't handle &foo being constant-folded */
STATIC OP*
myck_exists(pTHX_ OP *o)
{
    dVAR;
    
    if (o->op_flags & OPf_KIDS) {
        OP * const kid = cUNOPo->op_first;
        if (kid->op_type == OP_NULL && kid->op_targ == OP_ENTERSUB) {
            op_null(o);
            return (OP*)newSVOP(OP_CONST, 0, (SV*)&PL_sv_yes);
        }
        else if ( kid->op_type == OP_ENTERSUB ) {
            OP * aop = find_entersub_last_op(kid);
            SV * sv;
            
            if ( aop && aop->op_type == OP_CONST && (sv = cSVOPx_sv(aop)) ) {
                if ( SvOK(sv) && SvTYPE(sv) == SVt_PVCV ) {
                    op_null(o);
                    return (OP*)newSVOP(OP_CONST, 0, (SV*)&PL_sv_yes);
                }
            }
        }
    }

    
    return nxck_exists(aTHX_ o);
}

STATIC OP*
myck_defined(pTHX_ OP *o)
{
    if ((o->op_flags & OPf_KIDS)) {
        OP * first = cUNOPo->op_first;
        if (first->op_type == OP_NULL && first->op_targ == OP_ENTERSUB) {
            op_null(o);
            return (OP*)newSVOP(OP_CONST, 0, (SV*)&PL_sv_yes);
        }
        else if ( first->op_type == OP_ENTERSUB ) {
            OP * aop = find_entersub_last_op(first);
            SV * sv;
            
            if ( aop && aop->op_type == OP_CONST && (sv = cSVOPx_sv(aop)) ) {
                if ( SvOK(sv) && SvTYPE(sv) == SVt_PVCV ) {
                    op_null(o);
                    return (OP*)newSVOP(OP_CONST, 0, (SV*)&PL_sv_yes);
                }
            }
        }
    }
    
    return nxck_defined(aTHX_ o);
}

STATIC OP*
myck_entersubop(pTHX_ OP *entersubop)
{
    OP * o = nxck_entersubop(aTHX_ entersubop);
    optimize_entersub(o, PL_comppad_name);
    
    return o;
}

#ifdef USE_ITHREADS
STATIC SV*
clone_sv(pTHX_ SV* sv, tTHX owner)
#define clone_sv(s,v) clone_sv(aTHX_ (s), (v))
{
    CLONE_PARAMS param;
    param.stashes    = NULL;
    param.flags      = 0;
    param.proto_perl = owner;
 
    return sv_dup_inc(sv, &param);
}
 
#define clone_hv(s,v) MUTABLE_HV(clone_sv((SV*)(s), (v)))
#endif /* USE_ITHREADS */

#ifdef XopENTRY_set
static XOP my_cvxop, my_xscvxop;
#endif

MODULE = optimize::subs PACKAGE = optimize::subs

PROTOTYPES: DISABLE

BOOT:
{
    nxck_entersubop = PL_check[OP_ENTERSUB];
    nxck_exists     = PL_check[OP_EXISTS];
    nxck_defined    = PL_check[OP_DEFINED];
}

void
import(SV *classname)
CODE:
    PL_check[OP_ENTERSUB] = myck_entersubop;
    PL_check[OP_EXISTS]   = myck_exists;
    PL_check[OP_DEFINED]  = myck_defined;


void
unimport(SV *classname)
CODE:
    PL_check[OP_ENTERSUB] = nxck_entersubop;
    PL_check[OP_EXISTS]   = nxck_exists;
    PL_check[OP_DEFINED]  = nxck_defined;
    doof();
